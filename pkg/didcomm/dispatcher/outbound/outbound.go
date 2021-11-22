/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
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
	DIDRotator() *didrotate.DIDRotator
}

type connectionLookup interface {
	GetConnectionIDByDIDs(myDID, theirDID string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
	GetConnectionRecordByDIDs(myDID, theirDID string) (*connection.Record, error)
}

type connectionRecorder interface {
	connectionLookup
	SaveConnectionRecord(record *connection.Record) error
}

// Dispatcher dispatch msgs to destination.
type Dispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             transport.Packager
	transportReturnRoute string
	vdRegistry           vdr.Registry
	kms                  kms.KeyManager
	keyAgreementType     kms.KeyType
	connections          connectionRecorder
	mediaTypeProfiles    []string
	didRotator           *didrotate.DIDRotator
}

var logger = log.New("aries-framework/didcomm/dispatcher")

// NewOutbound return new dispatcher outbound instance.
func NewOutbound(prov provider) (*Dispatcher, error) {
	o := &Dispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
		vdRegistry:           prov.VDRegistry(),
		kms:                  prov.KMS(),
		keyAgreementType:     prov.KeyAgreementType(),
		mediaTypeProfiles:    prov.MediaTypeProfiles(),
		didRotator:           prov.DIDRotator(),
	}

	var err error

	o.connections, err = connection.NewRecorder(prov)
	if err != nil {
		return nil, fmt.Errorf("failed to init connection recorder: %w", err)
	}

	return o, nil
}

// SendToDID sends a message from myDID to the agent who owns theirDID.
func (o *Dispatcher) SendToDID(msg interface{}, myDID, theirDID string) error {
	myDocResolution, err := o.vdRegistry.Resolve(myDID)
	if err != nil {
		return fmt.Errorf("failed to resolve my DID: %w", err)
	}

	theirDocResolution, err := o.vdRegistry.Resolve(theirDID)
	if err != nil {
		return fmt.Errorf("failed to resolve their DID: %w", err)
	}

	myDoc := myDocResolution.DIDDocument
	theirDoc := theirDocResolution.DIDDocument

	connRec, err := o.getOrCreateConnection(myDoc, theirDoc)
	if err != nil {
		return fmt.Errorf("failed to fetch connection record: %w", err)
	}

	mediaTypes := make([]string, len(connRec.MediaTypeProfiles))
	copy(mediaTypes, connRec.MediaTypeProfiles)

	if didcommMsg, ok := msg.(service.DIDCommMsgMap); ok {
		didcommMsg, err = o.didRotator.HandleOutboundMessage(didcommMsg, connRec)
		if err != nil {
			logger.Warnf("did rotation failed on didcomm message: %w", err)
		} else {
			msg = &didcommMsg
		}
	}

	dest, err := service.CreateDestination(theirDoc)
	if err != nil {
		return fmt.Errorf(
			"outboundDispatcher.SendToDID failed to get didcomm destination for theirDID [%s]: %w", theirDID, err)
	}

	if len(mediaTypes) > 0 {
		dest.MediaTypeProfiles = mediaTypes
	}

	src, err := service.CreateDestination(myDoc)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.SendToDID failed to get didcomm destination for myDID [%s]: %w", myDID, err)
	}

	// We get at least one recipient key, so we can use the first one
	//  (right now, with only one key type used for sending)
	key := src.RecipientKeys[0]

	return o.Send(msg, key, dest)
}

func (o *Dispatcher) defaultMediaTypeProfiles() []string {
	mediaTypes := make([]string, len(o.mediaTypeProfiles))
	copy(mediaTypes, o.mediaTypeProfiles)

	return mediaTypes
}

func (o *Dispatcher) getOrCreateConnection(myDoc, theirDoc *diddoc.Doc) (*connection.Record, error) {
	record, err := o.connections.GetConnectionRecordByDIDs(myDoc.ID, theirDoc.ID)
	if err == nil {
		return record, nil
	} else if !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("failed to check if connection exists: %w", err)
	}

	// myDID and theirDID never had a connection, create a default connection for OOBless communication.
	logger.Debugf("no connection record found for myDID=%s theirDID=%s, will create", myDoc.ID, theirDoc.ID)

	newRecord := connection.Record{
		ConnectionID:      uuid.New().String(),
		MyDID:             myDoc.ID,
		TheirDID:          theirDoc.ID,
		State:             connection.StateNameCompleted,
		Namespace:         connection.MyNSPrefix,
		MediaTypeProfiles: o.defaultMediaTypeProfiles(),
	}

	err = o.connections.SaveConnectionRecord(&newRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to save new connection: %w", err)
	}

	return &newRecord, nil
}

// Send sends the message after packing with the sender key and recipient keys.
func (o *Dispatcher) Send(msg interface{}, senderKey string, des *service.Destination) error { // nolint:gocyclo
	// check if outbound accepts routing keys, else use recipient keys
	keys := des.RecipientKeys
	if len(des.RoutingKeys) != 0 {
		keys = des.RoutingKeys
	}

	var outboundTransport transport.OutboundTransport

	for _, v := range o.outboundTransports {
		if v.AcceptRecipient(keys) || v.Accept(des.ServiceEndpoint) {
			outboundTransport = v
			break
		}
	}

	if outboundTransport == nil {
		return fmt.Errorf("outboundDispatcher.Send: no transport found for destination: %+v", des)
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

	mtp := o.mediaTypeProfile(des)

	packedMsg, err := o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtp,
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

	_, err = outboundTransport.Send(packedMsg, des)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed to send msg using outbound transport: %w", err)
	}

	return nil
}

// Forward forwards the message without packing to the destination.
func (o *Dispatcher) Forward(msg interface{}, des *service.Destination) error {
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

func (o *Dispatcher) createForwardMessage(msg []byte, des *service.Destination) ([]byte, error) {
	forwardMsgType := service.ForwardMsgType

	mtProfile := o.mediaTypeProfile(des)

	var (
		senderKey []byte
		err       error
	)

	switch mtProfile {
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2EncryptedEnvelope,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeV2PlaintextPayload, transport.MediaTypeDIDCommV2Profile:
		// for DIDComm V2, do not set senderKey to force Anoncrypt packing. Only set the V2 forwardMsgType.
		forwardMsgType = service.ForwardMsgTypeV2
	default: // default is DIDComm V1, create a dummy key as senderKey
		// create key set
		_, senderKey, err = o.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("failed Create and export Encryption Key: %w", err)
		}

		senderDIDKey, _ := fingerprint.CreateDIDKey(senderKey)

		senderKey = []byte(senderDIDKey)
	}

	if len(des.RoutingKeys) == 0 {
		return msg, nil
	}

	// create forward message
	forward := &model.Forward{
		Type: forwardMsgType,
		ID:   uuid.New().String(),
		To:   des.RecipientKeys[0],
		Msg:  msg,
	}

	// convert forward message to bytes
	req, err := json.Marshal(forward)
	if err != nil {
		return nil, fmt.Errorf("failed marshal to bytes: %w", err)
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

func (o *Dispatcher) addTransportRouteOptions(req []byte, des *service.Destination) ([]byte, error) {
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

func (o *Dispatcher) mediaTypeProfile(des *service.Destination) string {
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
