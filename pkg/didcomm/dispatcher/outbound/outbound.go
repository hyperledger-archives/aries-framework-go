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
	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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
	DIDRotator() *middleware.DIDCommMessageMiddleware
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
	didcommV2Handler     *middleware.DIDCommMessageMiddleware
}

// legacyForward is DIDComm V1 route Forward msg as declared in
// https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0094-cross-domain-messaging/README.md
type legacyForward struct {
	Type string          `json:"@type,omitempty"`
	ID   string          `json:"@id,omitempty"`
	To   string          `json:"to,omitempty"`
	Msg  *model.Envelope `json:"msg,omitempty"`
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
		didcommV2Handler:     prov.DIDRotator(),
	}

	var err error

	o.connections, err = connection.NewRecorder(prov)
	if err != nil {
		return nil, fmt.Errorf("failed to init connection recorder: %w", err)
	}

	return o, nil
}

// SendToDID sends a message from myDID to the agent who owns theirDID.
func (o *Dispatcher) SendToDID(msg interface{}, myDID, theirDID string) error { // nolint:funlen,gocyclo,gocognit
	myDocResolution, err := o.vdRegistry.Resolve(myDID)
	if err != nil {
		return fmt.Errorf("failed to resolve my DID: %w", err)
	}

	theirDocResolution, err := o.vdRegistry.Resolve(theirDID)
	if err != nil {
		return fmt.Errorf("failed to resolve their DID: %w", err)
	}

	var connectionVersion service.Version

	didcommMsg, isMsgMap := msg.(service.DIDCommMsgMap)

	var isV2 bool

	if isMsgMap {
		isV2, err = service.IsDIDCommV2(&didcommMsg)
		if err == nil && isV2 {
			connectionVersion = service.V2
		} else {
			connectionVersion = service.V1
		}
	}

	connRec, err := o.getOrCreateConnection(myDID, theirDID, connectionVersion)
	if err != nil {
		return fmt.Errorf("failed to fetch connection record: %w", err)
	}

	var sendWithAnoncrypt bool

	if isMsgMap { // nolint:nestif
		didcommMsg = o.didcommV2Handler.HandleOutboundMessage(didcommMsg, connRec)

		if connRec.PeerDIDInitialState != "" {
			// we need to use anoncrypt if myDID is a peer DID being shared with the recipient through this message.
			sendWithAnoncrypt = true
		}

		// the first message sent using didcomm v2 should contain the invitation ID as pthid
		if connRec.DIDCommVersion == service.V2 && connRec.ParentThreadID != "" && connectionVersion == service.V2 {
			pthid, hasPthid := didcommMsg["pthid"].(string)

			thid, e := didcommMsg.ThreadID()
			if e == nil && didcommMsg.ID() == thid && (!hasPthid || pthid == "") {
				didcommMsg["pthid"] = connRec.ParentThreadID
			}
		}

		msg = &didcommMsg
	} else {
		didcommMsgPtr, ok := msg.(*service.DIDCommMsgMap)
		if ok {
			didcommMsg = *didcommMsgPtr
		} else {
			didcommMsg = service.NewDIDCommMsgMap(msg)
			msg = &didcommMsg
		}
	}

	dest, err := service.CreateDestination(theirDocResolution.DIDDocument)
	if err != nil {
		return fmt.Errorf(
			"outboundDispatcher.SendToDID failed to get didcomm destination for theirDID [%s]: %w", theirDID, err)
	}

	if len(connRec.MediaTypeProfiles) > 0 {
		dest.MediaTypeProfiles = make([]string, len(connRec.MediaTypeProfiles))
		copy(dest.MediaTypeProfiles, connRec.MediaTypeProfiles)
	}

	mtp := o.mediaTypeProfile(dest)
	switch mtp {
	case transport.MediaTypeV1PlaintextPayload, transport.MediaTypeV1EncryptedEnvelope,
		transport.MediaTypeRFC0019EncryptedEnvelope, transport.MediaTypeAIP2RFC0019Profile:
		sendWithAnoncrypt = false
	}

	if sendWithAnoncrypt {
		return o.Send(msg, "", dest)
	}

	src, err := service.CreateDestination(myDocResolution.DIDDocument)
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

// getOrCreateConnection returns true iff it created a new connection rather than fetching one.
func (o *Dispatcher) getOrCreateConnection(myDID, theirDID string, connectionVersion service.Version,
) (*connection.Record, error) {
	record, err := o.connections.GetConnectionRecordByDIDs(myDID, theirDID)
	if err == nil {
		return record, nil
	} else if !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("failed to check if connection exists: %w", err)
	}

	// myDID and theirDID never had a connection, create a default connection for OOBless communication.
	logger.Debugf("no connection record found for myDID=%s theirDID=%s, will create", myDID, theirDID)

	newRecord := connection.Record{
		ConnectionID:   uuid.New().String(),
		MyDID:          myDID,
		TheirDID:       theirDID,
		State:          connection.StateNameCompleted,
		Namespace:      connection.MyNSPrefix,
		DIDCommVersion: connectionVersion,
	}

	if connectionVersion == service.V2 {
		newRecord.ServiceEndPoint = commonmodel.NewDIDCommV2Endpoint(
			[]commonmodel.DIDCommV2Endpoint{{Accept: o.defaultMediaTypeProfiles()}})
	} else {
		newRecord.MediaTypeProfiles = o.defaultMediaTypeProfiles()
	}

	err = o.connections.SaveConnectionRecord(&newRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to save new connection: %w", err)
	}

	return &newRecord, nil
}

// Send sends the message after packing with the sender key and recipient keys.
func (o *Dispatcher) Send(msg interface{}, senderKey string, des *service.Destination) error { // nolint:funlen,gocyclo
	// check if outbound accepts routing keys, else use recipient keys
	keys := des.RecipientKeys
	if routingKeys, err := des.ServiceEndpoint.RoutingKeys(); err == nil && len(routingKeys) > 0 { // DIDComm V2
		keys = routingKeys
	} else if len(des.RoutingKeys) > 0 { // DIDComm V1
		keys = routingKeys
	}

	var outboundTransport transport.OutboundTransport

	for _, v := range o.outboundTransports {
		uri, err := des.ServiceEndpoint.URI()
		if err != nil {
			logger.Debugf("destination ServiceEndpoint empty: %w, it will not be checked", err)
		}

		if v.AcceptRecipient(keys) || v.Accept(uri) {
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

	var fromKey []byte

	if len(senderKey) > 0 {
		fromKey = []byte(senderKey)
	}

	packedMsg, err := o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtp,
		Message:          req,
		FromKey:          fromKey,
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
	var (
		uri string
		err error
	)

	uri, err = des.ServiceEndpoint.URI()
	if err != nil {
		logger.Debugf("destination serviceEndpoint forward URI is not set: %w, will skip value", err)
	}

	for _, v := range o.outboundTransports {
		if !v.AcceptRecipient(des.RecipientKeys) {
			if !v.Accept(uri) {
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

	return fmt.Errorf("outboundDispatcher.Forward: no transport found for serviceEndpoint: %s", uri)
}

func (o *Dispatcher) createForwardMessage(msg []byte, des *service.Destination) ([]byte, error) {
	mtProfile := o.mediaTypeProfile(des)

	var (
		forwardMsgType string
		err            error
	)

	switch mtProfile {
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2EncryptedEnvelope,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeV2PlaintextPayload, transport.MediaTypeDIDCommV2Profile:
		// for DIDComm V2, do not set senderKey to force Anoncrypt packing. Only set the V2 forwardMsgType.
		forwardMsgType = service.ForwardMsgTypeV2
	default: // default is DIDComm V1
		forwardMsgType = service.ForwardMsgType
	}

	routingKeys, err := des.ServiceEndpoint.RoutingKeys()
	if err != nil {
		logger.Debugf("des.ServiceEndpoint.RoutingKeys() (didcomm v2) returned an error %w, "+
			"will check routinKeys (didcomm v1) array", err)
	}

	if len(routingKeys) == 0 {
		if len(des.RoutingKeys) == 0 {
			return msg, nil
		}

		routingKeys = des.RoutingKeys
	}

	fwdKeys := append([]string{des.RecipientKeys[0]}, routingKeys...)

	packedMsg, err := o.createPackedNestedForwards(msg, fwdKeys, forwardMsgType, mtProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to create packed nested forwards: %w", err)
	}

	return packedMsg, nil
}

func (o *Dispatcher) createPackedNestedForwards(msg []byte, routingKeys []string, fwdMsgType, mtProfile string) ([]byte, error) { //nolint: lll
	for i, key := range routingKeys {
		if i+1 >= len(routingKeys) {
			break
		}
		// create forward message
		forward := model.Forward{
			Type: fwdMsgType,
			ID:   uuid.New().String(),
			To:   key,
			Msg:  msg,
		}

		var err error

		msg, err = o.packForward(forward, []string{routingKeys[i+1]}, mtProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to pack forward msg: %w", err)
		}
	}

	return msg, nil
}

func (o *Dispatcher) packForward(fwd model.Forward, toKeys []string, mtProfile string) ([]byte, error) {
	env := &model.Envelope{}

	var (
		forward interface{}
		err     error
		req     []byte
	)
	// try to convert msg to Envelope
	err = json.Unmarshal(fwd.Msg, env)
	if err == nil {
		// Convert did:key to base58 to support legacy profile type
		if strings.HasPrefix(fwd.To, "did:key") && mtProfile == transport.LegacyDIDCommV1Profile {
			fwd.To, err = kmsdidkey.GetBase58PubKeyFromDIDKey(fwd.To)
			if err != nil {
				return nil, err
			}
		}
		// create legacy forward
		forward = legacyForward{
			Type: fwd.Type,
			ID:   fwd.ID,
			To:   fwd.To,
			Msg:  env,
		}
	} else {
		forward = fwd
	}
	// convert forward message to bytes
	req, err = json.Marshal(forward)
	if err != nil {
		return nil, fmt.Errorf("failed marshal to bytes: %w", err)
	}

	var packedMsg []byte
	packedMsg, err = o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtProfile,
		Message:          req,
		FromKey:          []byte{},
		ToKeys:           toKeys,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to pack forward msg: %w", err)
	}

	return packedMsg, nil
}

func (o *Dispatcher) addTransportRouteOptions(req []byte, des *service.Destination) ([]byte, error) {
	// don't add transport route options for forward messages
	if routingKeys, err := des.ServiceEndpoint.RoutingKeys(); err == nil && len(routingKeys) > 0 {
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
	var (
		mt     string
		accept []string
		err    error
	)

	if accept, err = des.ServiceEndpoint.Accept(); err != nil || len(accept) == 0 { // didcomm v2
		accept = des.MediaTypeProfiles // didcomm v1
	}

	if len(accept) > 0 {
		for _, mtp := range accept {
			switch mtp {
			case transport.MediaTypeV1PlaintextPayload, transport.MediaTypeRFC0019EncryptedEnvelope,
				transport.MediaTypeAIP2RFC0019Profile, transport.MediaTypeProfileDIDCommAIP1,
				transport.LegacyDIDCommV1Profile:
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
