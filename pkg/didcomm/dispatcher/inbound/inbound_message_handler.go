/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cenkalti/backoff/v4"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

var logger = log.New("dispatcher/inbound")

const (
	kaIdentifier = "#"
)

// MessageHandler handles inbound envelopes, processing then dispatching to a protocol service based on the
// message type.
type MessageHandler struct {
	didConnectionStore     did.ConnectionStore
	msgSvcProvider         api.MessageServiceProvider
	services               []dispatcher.ProtocolService
	getDIDsBackOffDuration time.Duration
	getDIDsMaxRetries      uint64
	messenger              service.InboundMessenger
	initialized            bool
}

type provider interface {
	DIDConnectionStore() did.ConnectionStore
	MessageServiceProvider() api.MessageServiceProvider
	AllServices() []dispatcher.ProtocolService
	GetDIDsBackOffDuration() time.Duration
	GetDIDsMaxRetries() uint64
	InboundMessenger() service.InboundMessenger
}

// NewInboundMessageHandler creates an inbound message handler, that processes inbound message Envelopes,
// and dispatches them to the appropriate ProtocolService.
func NewInboundMessageHandler(p provider) *MessageHandler {
	h := MessageHandler{}
	h.Initialize(p)

	return &h
}

// Initialize initializes the MessageHandler. Any call beyond the first is a no-op.
func (handler *MessageHandler) Initialize(p provider) {
	if handler.initialized {
		return
	}

	handler.didConnectionStore = p.DIDConnectionStore()
	handler.msgSvcProvider = p.MessageServiceProvider()
	handler.services = p.AllServices()
	handler.getDIDsBackOffDuration = p.GetDIDsBackOffDuration()
	handler.getDIDsMaxRetries = p.GetDIDsMaxRetries()
	handler.messenger = p.InboundMessenger()

	handler.initialized = true
}

// HandleInboundEnvelope handles an inbound envelope, dispatching it to the appropriate ProtocolService.
func (handler *MessageHandler) HandleInboundEnvelope(envelope *transport.Envelope) error { // nolint:gocyclo,funlen
	var (
		msg service.DIDCommMsgMap
		err error
	)

	msg, err = service.ParseDIDCommMsgMap(envelope.Message)
	if err != nil {
		return err
	}

	isV2, err := service.IsDIDCommV2(&msg)
	if err != nil {
		return err
	}

	// if msg is a didcomm v2 message, do additional handling
	if isV2 {
		// TODO: handle DID rotation and other didcomm/v2 protocol-agnostic message handling here
		logger.Debugf("didcomm v2 message handling before service...")
	}

	// find the service which accepts the message type
	for _, svc := range handler.services {
		if svc.Accept(msg.Type()) {
			var myDID, theirDID string

			switch svc.Name() {
			// perf: DID exchange doesn't require myDID and theirDID
			case didexchange.DIDExchange:
			default:
				myDID, theirDID, err = handler.getDIDs(envelope)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}
			}

			_, err = svc.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))

			return err
		}
	}

	if !isV2 {
		// in case of no services are registered for given message type, and message is didcomm v1,
		// find generic inbound services registered for given message header
		for _, svc := range handler.msgSvcProvider.Services() {
			h := struct {
				Purpose []string `json:"~purpose"`
			}{}
			err = msg.Decode(&h)

			if err != nil {
				return err
			}

			if svc.Accept(msg.Type(), h.Purpose) {
				myDID, theirDID, err := handler.getDIDs(envelope)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}

				return handler.tryToHandle(svc, msg, service.NewDIDCommContext(myDID, theirDID, nil))
			}
		}
	}

	return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
}

//nolint:funlen,gocyclo
func (handler *MessageHandler) getDIDs(envelope *transport.Envelope) (string, string, error) {
	var (
		myDID    string
		theirDID string
		err      error
	)

	myDID, err = handler.getDIDGivenKey(envelope.ToKey)
	if err != nil {
		return myDID, theirDID, err
	}

	theirDID, err = handler.getDIDGivenKey(envelope.FromKey)
	if err != nil {
		return myDID, theirDID, err
	}

	return myDID, theirDID, backoff.Retry(func() error {
		var notFound bool

		if myDID == "" {
			myDID, err = handler.didConnectionStore.GetDID(base58.Encode(envelope.ToKey))
			if errors.Is(err, did.ErrNotFound) {
				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers only, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.ToKey)
				myDID, err = handler.didConnectionStore.GetDID(didKey)
			}

			if errors.Is(err, did.ErrNotFound) {
				notFound = true
			} else if err != nil {
				myDID = ""
				return fmt.Errorf("failed to get my did: %w", err)
			}
		}

		if envelope.FromKey == nil {
			return nil
		}

		if theirDID == "" {
			theirDID, err = handler.didConnectionStore.GetDID(base58.Encode(envelope.FromKey))
			if errors.Is(err, did.ErrNotFound) {
				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.FromKey)
				theirDID, err = handler.didConnectionStore.GetDID(didKey)
			}

			if err == nil {
				return nil
			}

			if notFound && errors.Is(err, did.ErrNotFound) {
				// if neither DID is found, using either base58 key or did:key as lookup key
				return nil
			}

			theirDID = ""
			return fmt.Errorf("failed to get their did: %w", err)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(handler.getDIDsBackOffDuration), handler.getDIDsMaxRetries))
}

// getDIDGivenKey returns a did:key if the input key is a JWK. If the input key is not a JWK, returns the empty string.
// An error is returned if the key is a JWK but fails to be converted to a did:key.
func (handler *MessageHandler) getDIDGivenKey(key []byte) (string, error) {
	var (
		err    error
		retDID string
	)

	// nolint: gocritic
	if strings.Index(string(key), kaIdentifier) > 0 &&
		strings.Index(string(key), "\"kid\":\"did:") > 0 {
		retDID, err = pubKeyToDID(key)
		if err != nil {
			return "", fmt.Errorf("getDID: %w", err)
		}

		logger.Debugf("envelope Key as DID: %v", retDID)

		return retDID, nil
	}

	return "", nil
}

func pubKeyToDID(key []byte) (string, error) {
	toKey := &crypto.PublicKey{}

	err := json.Unmarshal(key, toKey)
	if err != nil {
		return "", fmt.Errorf("pubKeyToDID: unmarshal key: %w", err)
	}

	return toKey.KID[:strings.Index(toKey.KID, kaIdentifier)], nil
}

func (handler *MessageHandler) tryToHandle(
	svc service.InboundHandler, msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	if err := handler.messenger.HandleInbound(msg, ctx); err != nil {
		return fmt.Errorf("messenger HandleInbound: %w", err)
	}

	_, err := svc.HandleInbound(msg, ctx)

	return err
}
