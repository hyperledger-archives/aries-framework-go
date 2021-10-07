/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// provider interface for outbound ctx.
type provider interface {
	Packager() transport.Packager
	OutboundTransports() []transport.OutboundTransport
	TransportReturnRoute() string
	VDRegistry() vdr.Registry
	KMS() kms.KeyManager
	KeyAgreementType() kms.KeyType
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
	MediaTypeProfiles() []string
}

type connectionLookup interface {
	GetConnectionIDByDIDs(myDID, theirDID string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
}

// OutboundDispatcher dispatch msgs to destination.
type OutboundDispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             transport.Packager
	transportReturnRoute string
	vdRegistry           vdr.Registry
	kms                  kms.KeyManager
	keyAgreementType     kms.KeyType
	connections          connectionLookup
	mediaTypeProfiles    []string
}

var logger = log.New("aries-framework/didcomm/dispatcher")

// NewOutbound return new dispatcher outbound instance.
func NewOutbound(prov provider) (*OutboundDispatcher, error) {
	o := &OutboundDispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
		vdRegistry:           prov.VDRegistry(),
		kms:                  prov.KMS(),
		keyAgreementType:     prov.KeyAgreementType(),
		mediaTypeProfiles:    prov.MediaTypeProfiles(),
	}

	var err error

	o.connections, err = connection.NewLookup(prov)
	if err != nil {
		return nil, fmt.Errorf("failed to init connections lookup: %w", err)
	}

	return o, nil
}

// SendToDID sends a message from myDID to the agent who owns theirDID.
func (o *OutboundDispatcher) SendToDID(msg interface{}, myDID, theirDID string) error {
	var mediaTypes []string

	connID, err := o.connections.GetConnectionIDByDIDs(myDID, theirDID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			// myDID and theirDID never had a connection, use default agent media type.
			logger.Debugf("SendToDID: will go connectionless since failed to fetch connection ID for myDID=%s "+
				"theirDID=%s: %w", myDID, theirDID, err)

			mediaTypes = o.defaultMediaTypeProfiles()
		} else {
			return fmt.Errorf("SendToDID: failed to fetch connection ID for myDID=%s "+
				"theirDID=%s: %w", myDID, theirDID, err)
		}
	}

	if connID != "" {
		mediaTypes, err = o.mediaTypeProfilesFromConnection(mediaTypes, connID)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.SendToDID: %w", err)
		}
	}

	dest, err := service.GetDestination(theirDID, o.vdRegistry)
	if err != nil {
		return fmt.Errorf(
			"outboundDispatcher.SendToDID failed to get didcomm destination for theirDID [%s]: %w", theirDID, err)
	}

	if len(mediaTypes) > 0 {
		dest.MediaTypeProfiles = mediaTypes
	}

	src, err := service.GetDestination(myDID, o.vdRegistry)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.SendToDID failed to get didcomm destination for myDID [%s]: %w", myDID, err)
	}

	// We get at least one recipient key, so we can use the first one
	//  (right now, with only one key type used for sending)
	key := src.RecipientKeys[0]

	return o.Send(msg, key, dest)
}

func (o *OutboundDispatcher) defaultMediaTypeProfiles() []string {
	mediaTypes := make([]string, len(o.mediaTypeProfiles))
	copy(mediaTypes, o.mediaTypeProfiles)

	return mediaTypes
}

func (o *OutboundDispatcher) mediaTypeProfilesFromConnection(mediaTypes []string, connID string) ([]string, error) {
	record, err := o.connections.GetConnectionRecord(connID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			if len(mediaTypes) == 0 {
				// myDID and theirDID don't have a connection record but do have a connID, use default agent media type.
				logger.Debugf("SendToDID: will go connectionless since failed to fetch connection record for "+
					"connID:%s: %w", connID, err)

				mediaTypes = o.defaultMediaTypeProfiles()
			}
		} else {
			return nil, fmt.Errorf("failed to fetch connection record for connID=%s: %w", connID, err)
		}
	}

	if record != nil {
		mediaTypes = make([]string, len(record.MediaTypeProfiles))
		copy(mediaTypes, record.MediaTypeProfiles)
	}

	return mediaTypes, nil
}

// Send sends the message after packing with the sender key and recipient keys.
func (o *OutboundDispatcher) Send(msg interface{}, senderKey string, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		// check if outbound accepts routing keys, else use recipient keys
		keys := des.RecipientKeys
		if len(des.RoutingKeys) != 0 {
			keys = des.RoutingKeys
		}

		if !v.AcceptRecipient(keys) {
			if !v.Accept(des.ServiceEndpoint) {
				continue
			}
		}

		req, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed marshal to bytes: %w", err)
		}

		// update the outbound message with transport return route option [all or thread]
		req, err = o.addTransportRouteOptions(req, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to add transport route options: %w", err)
		}

		packedMsg, err := o.packager.PackMessage(&transport.Envelope{
			MediaTypeProfile: o.mediaTypeProfile(des),
			Message:          req,
			FromKey:          []byte(senderKey),
			ToKeys:           des.RecipientKeys,
		})
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to pack msg: %w", err)
		}

		// set the return route option
		des.TransportReturnRoute = o.transportReturnRoute

		packedMsg, err = o.createForwardMessage(packedMsg, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to create forward msg: %w", err)
		}

		_, err = v.Send(packedMsg, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Send: failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("outboundDispatcher.Send: no transport found for destination: %+v", des)
}

// Forward forwards the message without packing to the destination.
func (o *OutboundDispatcher) Forward(msg interface{}, des *service.Destination) error {
	for _, v := range o.outboundTransports {
		if !v.AcceptRecipient(des.RecipientKeys) {
			if !v.Accept(des.ServiceEndpoint) {
				continue
			}
		}

		req, err := json.Marshal(msg)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Forward: failed marshal to bytes: %w", err)
		}

		_, err = v.Send(req, des)
		if err != nil {
			return fmt.Errorf("outboundDispatcher.Forward: failed to send msg using outbound transport: %w", err)
		}

		return nil
	}

	return fmt.Errorf("outboundDispatcher.Forward: no transport found for serviceEndpoint: %s", des.ServiceEndpoint)
}

func (o *OutboundDispatcher) createForwardMessage(msg []byte, des *service.Destination) ([]byte, error) {
	if len(des.RoutingKeys) == 0 {
		return msg, nil
	}

	// create forward message
	forward := &model.Forward{
		Type: service.ForwardMsgType,
		ID:   uuid.New().String(),
		To:   des.RecipientKeys[0],
		Msg:  msg,
	}

	// convert forward message to bytes
	req, err := json.Marshal(forward)
	if err != nil {
		return nil, fmt.Errorf("failed marshal to bytes: %w", err)
	}

	mtProfile := o.mediaTypeProfile(des)

	var senderKey []byte

	switch mtProfile {
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2EncryptedEnvelope,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeV2PlaintextPayload, transport.MediaTypeDIDCommV2Profile:
		break // for DIDComm V2, do not set senderKey to force Anoncrypt packing.
	default: // default is DIDComm V1, create a dummy key as senderKey
		// create key set
		_, senderKey, err = o.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("failed Create and export Encryption Key: %w", err)
		}

		senderDIDKey, _ := fingerprint.CreateDIDKey(senderKey)

		senderKey = []byte(senderDIDKey)
	}

	packedMsg, err := o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtProfile,
		Message:          req,
		FromKey:          senderKey,
		ToKeys:           des.RoutingKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pack forward msg: %w", err)
	}

	return packedMsg, nil
}

func (o *OutboundDispatcher) addTransportRouteOptions(req []byte, des *service.Destination) ([]byte, error) {
	// dont add transport route options for forward messages
	if len(des.RoutingKeys) != 0 {
		return req, nil
	}

	if o.transportReturnRoute == decorator.TransportReturnRouteAll ||
		o.transportReturnRoute == decorator.TransportReturnRouteThread {
		// create the decorator with the option set in the framework
		transportDec := &decorator.Transport{ReturnRoute: &decorator.ReturnRoute{Value: o.transportReturnRoute}}

		transportDecJSON, jsonErr := json.Marshal(transportDec)
		if jsonErr != nil {
			return nil, fmt.Errorf("json marshal : %w", jsonErr)
		}

		request := string(req)
		index := strings.Index(request, "{")

		// add transport route option decorator to the original request
		req = []byte(request[:index+1] + string(transportDecJSON)[1:len(string(transportDecJSON))-1] + "," +
			request[index+1:])
	}

	return req, nil
}

func (o *OutboundDispatcher) mediaTypeProfile(des *service.Destination) string {
	mt := ""

	if len(des.MediaTypeProfiles) > 0 {
		for _, mtp := range des.MediaTypeProfiles {
			switch mtp {
			case transport.MediaTypeV1PlaintextPayload, transport.MediaTypeRFC0019EncryptedEnvelope,
				transport.MediaTypeAIP2RFC0019Profile, transport.MediaTypeProfileDIDCommAIP1:
				// overridable with higher priority media type.
				if mt == "" {
					mt = mtp
				}
			case transport.MediaTypeV1EncryptedEnvelope, transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
				transport.MediaTypeAIP2RFC0587Profile:
				mt = mtp
			case transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2PlaintextPayload,
				transport.MediaTypeDIDCommV2Profile:
				// V2 is the highest priority, if found use it directly.
				return mtp
			}
		}
	}

	if mt == "" {
		return o.defaultMediaTypeProfiles()[0]
	}

	return mt
}
