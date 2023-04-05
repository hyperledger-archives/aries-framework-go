/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/didcommutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	connectionstore "github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	stateNameNoop = "noop"
	stateNameNull = "null"
	// StateIDInvited marks the invited phase of the did-exchange protocol.
	StateIDInvited = "invited"
	// StateIDRequested marks the requested phase of the did-exchange protocol.
	StateIDRequested = "requested"
	// StateIDResponded marks the responded phase of the did-exchange protocol.
	StateIDResponded = "responded"
	// StateIDCompleted marks the completed phase of the did-exchange protocol.
	StateIDCompleted = "completed"
	// StateIDAbandoned marks the abandoned phase of the did-exchange protocol.
	StateIDAbandoned   = "abandoned"
	ackStatusOK        = "ok"
	didCommServiceType = "did-communication"
	// legacyDIDCommServiceType for aca-py interop.
	legacyDIDCommServiceType = "IndyAgent"
	// DIDComm V2 service type ref: https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint
	didCommV2ServiceType       = "DIDCommMessaging"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	bls12381G2Key2020          = "Bls12381G2Key2020"
	jsonWebKey2020             = "JsonWebKey2020"
	didMethod                  = "peer"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
)

var errVerKeyNotFound = errors.New("verkey not found")

// state action for network call.
type stateAction func() error

// The did-exchange protocol's state.
type state interface {
	// Name of this state.
	Name() string

	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool

	// ExecuteInbound this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record,
		state state, action stateAction, err error)
}

// Returns the state towards which the protocol will transition to if the msgType is processed.
func stateFromMsgType(msgType string) (state, error) {
	switch msgType {
	case InvitationMsgType, oobMsgType:
		return &invited{}, nil
	case RequestMsgType:
		return &requested{}, nil
	case ResponseMsgType:
		return &responded{}, nil
	case AckMsgType, CompleteMsgType:
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msgType)
	}
}

// Returns the state representing the name.
func stateFromName(name string) (state, error) {
	switch name {
	case stateNameNoop:
		return &noOp{}, nil
	case stateNameNull:
		return &null{}, nil
	case StateIDInvited:
		return &invited{}, nil
	case StateIDRequested:
		return &requested{}, nil
	case StateIDResponded:
		return &responded{}, nil
	case StateIDCompleted:
		return &completed{}, nil
	case StateIDAbandoned:
		return &abandoned{}, nil
	default:
		return nil, fmt.Errorf("invalid state name %s", name)
	}
}

type noOp struct{}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	return nil, nil, nil, errors.New("cannot execute no-op")
}

// null state.
type null struct{}

func (s *null) Name() string {
	return stateNameNull
}

func (s *null) CanTransitionTo(next state) bool {
	return StateIDInvited == next.Name() || StateIDRequested == next.Name()
}

func (s *null) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	return &connectionstore.Record{}, &noOp{}, nil, nil
}

// invited state.
type invited struct{}

func (s *invited) Name() string {
	return StateIDInvited
}

func (s *invited) CanTransitionTo(next state) bool {
	return StateIDRequested == next.Name()
}

func (s *invited) ExecuteInbound(msg *stateMachineMsg, _ string, _ *context) (*connectionstore.Record,
	state, stateAction, error) {
	if msg.Type() != InvitationMsgType && msg.Type() != oobMsgType {
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}

	return msg.connRecord, &requested{}, func() error { return nil }, nil
}

// requested state.
type requested struct{}

func (s *requested) Name() string {
	return StateIDRequested
}

func (s *requested) CanTransitionTo(next state) bool {
	return StateIDResponded == next.Name()
}

func (s *requested) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	switch msg.Type() {
	case oobMsgType:
		oobInvitation := &OOBInvitation{}

		err := msg.Decode(oobInvitation)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode oob invitation: %w", err)
		}

		action, record, err := ctx.handleInboundOOBInvitation(oobInvitation, thid, msg.options, msg.connRecord)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to handle inbound oob invitation : %w", err)
		}

		return record, &noOp{}, action, nil
	case InvitationMsgType:
		invitation := &Invitation{}

		err := msg.Decode(invitation)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("JSON unmarshalling of invitation: %w", err)
		}

		action, connRecord, err := ctx.handleInboundInvitation(invitation, thid, msg.options, msg.connRecord)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound invitation: %w", err)
		}

		return connRecord, &noOp{}, action, nil
	case RequestMsgType:
		return msg.connRecord, &responded{}, func() error { return nil }, nil
	default:
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}
}

// responded state.
type responded struct{}

func (s *responded) Name() string {
	return StateIDResponded
}

func (s *responded) CanTransitionTo(next state) bool {
	return StateIDCompleted == next.Name()
}

func (s *responded) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	switch msg.Type() {
	case RequestMsgType:
		request := &Request{}

		err := msg.Decode(request)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("JSON unmarshalling of request: %w", err)
		}

		action, connRecord, err := ctx.handleInboundRequest(request, msg.options, msg.connRecord)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound request: %w", err)
		}

		return connRecord, &noOp{}, action, nil
	case ResponseMsgType, CompleteMsgType:
		return msg.connRecord, &completed{}, func() error { return nil }, nil
	default:
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}
}

// completed state.
type completed struct{}

func (s *completed) Name() string {
	return StateIDCompleted
}

func (s *completed) CanTransitionTo(next state) bool {
	return false
}

func (s *completed) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	switch msg.Type() {
	case ResponseMsgType:
		response := &Response{}

		err := msg.Decode(response)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("JSON unmarshalling of response: %w", err)
		}

		action, connRecord, err := ctx.handleInboundResponse(response)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound response: %w", err)
		}

		return connRecord, &noOp{}, action, nil
	case AckMsgType:
		action := func() error { return nil }
		return msg.connRecord, &noOp{}, action, nil
	case CompleteMsgType:
		complete := &Complete{}

		err := msg.Decode(complete)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("JSON unmarshalling of complete: %w", err)
		}

		action := func() error { return nil }

		if msg.connRecord == nil {
			return nil, &noOp{}, action, nil
		}

		connRec := *msg.connRecord

		return &connRec, &noOp{}, action, nil
	default:
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}
}

// abandoned state.
type abandoned struct{}

func (s *abandoned) Name() string {
	return StateIDAbandoned
}

func (s *abandoned) CanTransitionTo(next state) bool {
	return false
}

func (s *abandoned) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.Record,
	state, stateAction, error) {
	return nil, nil, nil, errors.New("not implemented")
}

func (ctx *context) handleInboundOOBInvitation(oobInv *OOBInvitation, thid string, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	svc, err := ctx.getServiceBlock(oobInv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get service block: %w", err)
	}

	dest := &service.Destination{
		RecipientKeys:     svc.RecipientKeys,
		ServiceEndpoint:   svc.ServiceEndpoint,
		RoutingKeys:       svc.RoutingKeys,
		MediaTypeProfiles: svc.Accept,
	}

	connRec.ThreadID = thid

	return ctx.createInvitedRequest(dest, oobInv.MyLabel, thid, connRec.ParentThreadID, options, connRec)
}

func (ctx *context) handleInboundInvitation(invitation *Invitation, thid string, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	// create a destination from invitation
	destination, err := ctx.getDestination(invitation)
	if err != nil {
		return nil, nil, err
	}

	pid := invitation.ID
	if connRec.Implicit {
		pid = invitation.DID
	}

	return ctx.createInvitedRequest(destination, getLabel(options), thid, pid, options, connRec)
}

func (ctx *context) createInvitedRequest(destination *service.Destination, label, thid, pthid string, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	request := &Request{
		Type:  RequestMsgType,
		ID:    thid,
		Label: label,
		Thread: &decorator.Thread{
			PID: pthid,
		},
	}

	accept, err := destination.ServiceEndpoint.Accept() // didcomm v2
	if err != nil {
		accept = destination.MediaTypeProfiles // didcomm v1
	}

	// get did document to use in exchange request
	myDIDDoc, err := ctx.getMyDIDDoc(getPublicDID(options), getRouterConnections(options),
		serviceTypeByMediaProfile(accept))
	if err != nil {
		return nil, nil, err
	}

	connRec.MyDID = myDIDDoc.ID

	senderKey, err := recipientKeyAsDIDKey(myDIDDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("getting recipient key: %w", err)
	}

	// Interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	requestDidDoc, err := convertPeerToSov(myDIDDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("converting my did doc to a 'sov' doc for request message: %w", err)
	}

	// Interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if ctx.doACAPyInterop {
		request.DID = strings.TrimPrefix(myDIDDoc.ID, "did:sov:")
	} else {
		request.DID = myDIDDoc.ID
	}

	request.DocAttach, err = ctx.didDocAttachment(requestDidDoc, senderKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating did doc attachment for request: %w", err)
	}

	return func() error {
		return ctx.outboundDispatcher.Send(request, senderKey, destination)
	}, connRec, nil
}

func serviceTypeByMediaProfile(mediaTypeProfiles []string) string {
	serviceType := didCommServiceType

	for _, mtp := range mediaTypeProfiles {
		var breakFor bool

		switch mtp {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile,
			transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
			transport.MediaTypeV1EncryptedEnvelope:
			serviceType = didCommV2ServiceType

			breakFor = true
		}

		if breakFor {
			break
		}
	}

	return serviceType
}

// nolint:gocyclo,funlen
func (ctx *context) handleInboundRequest(request *Request, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	logger.Debugf("handling request: %#v", request)

	// Interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if ctx.doACAPyInterop && !strings.HasPrefix(request.DID, "did") {
		request.DID = "did:peer:" + request.DID
	}

	requestDidDoc, err := ctx.resolveDidDocFromMessage(request.DID, request.DocAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve did doc from exchange request: %w", err)
	}

	// get did document that will be used in exchange response
	// (my did doc)
	myDID := getPublicDID(options)

	destination, err := service.CreateDestination(requestDidDoc)
	if err != nil {
		return nil, nil, err
	}

	var serviceType string
	if len(requestDidDoc.Service) > 0 {
		serviceType = didcommutil.GetServiceType(requestDidDoc.Service[0].Type)
	} else {
		accept, e := destination.ServiceEndpoint.Accept()
		if e != nil {
			accept = []string{}
		}

		serviceType = serviceTypeByMediaProfile(accept)
	}

	responseDidDoc, err := ctx.getMyDIDDoc(myDID, getRouterConnections(options), serviceType)
	if err != nil {
		return nil, nil, fmt.Errorf("get response did doc and connection: %w", err)
	}

	var senderVerKey string

	if myDID != "" { // empty myDID means a new DID was just created and not exchanged yet, use did:key instead
		senderVerKey, err = recipientKey(responseDidDoc)
		if err != nil {
			return nil, nil, fmt.Errorf("get recipient key: %w", err)
		}
	} else {
		senderVerKey, err = recipientKeyAsDIDKey(responseDidDoc)
		if err != nil {
			return nil, nil, fmt.Errorf("get recipient key as did:key: %w", err)
		}
	}

	connRec.MyDID = responseDidDoc.ID

	if ctx.doACAPyInterop {
		// Interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
		responseDidDoc, err = convertPeerToSov(responseDidDoc)
		if err != nil {
			return nil, nil, fmt.Errorf("converting my did doc to a 'sov' doc for response message: %w", err)
		}
	}

	response, err := ctx.prepareResponse(request, responseDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("preparing response: %w", err)
	}

	connRec.TheirDID = request.DID
	connRec.TheirLabel = request.Label

	accept, err := destination.ServiceEndpoint.Accept()
	if err != nil {
		accept = []string{}
	}

	if len(accept) > 0 {
		connRec.MediaTypeProfiles = accept
	}

	// send exchange response
	return func() error {
		return ctx.outboundDispatcher.Send(response, senderVerKey, destination)
	}, connRec, nil
}

func (ctx *context) prepareResponse(request *Request, responseDidDoc *did.Doc) (*Response, error) {
	// prepare the response
	response := &Response{
		Type: ResponseMsgType,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
	}

	if request.Thread != nil {
		response.Thread.PID = request.Thread.PID
	}

	invitationKey, err := ctx.getVerKey(request.Thread.PID)
	if err != nil {
		return nil, fmt.Errorf("getting sender verkey: %w", err)
	}

	docAttach, err := ctx.didDocAttachment(responseDidDoc, invitationKey)
	if err != nil {
		return nil, err
	}

	// Interop: aca-py expects naked DID method-specific identifier for sov DIDs
	// https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	response.DID = strings.TrimPrefix(responseDidDoc.ID, "did:sov:")
	response.DocAttach = docAttach

	return response, nil
}

func (ctx *context) didDocAttachment(doc *did.Doc, myVerKey string) (*decorator.Attachment, error) {
	docBytes, err := doc.SerializeInterop()
	if err != nil {
		return nil, fmt.Errorf("marshaling did doc: %w", err)
	}

	docAttach := &decorator.Attachment{
		MimeType: "application/json",
		Data: decorator.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(docBytes),
		},
	}

	// Interop: signing did_doc~attach has been removed from the spec, but aca-py still verifies signatures
	// TODO make aca-py issue
	if ctx.doACAPyInterop {
		pubKeyBytes, err := ctx.resolvePublicKey(myVerKey)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve public key: %w", err)
		}

		// TODO: use dynamic context KeyType
		signingKID, err := jwkkid.CreateKID(pubKeyBytes, kms.ED25519Type)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KID from public key: %w", err)
		}

		kh, err := ctx.kms.Get(signingKID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key handle: %w", err)
		}

		err = docAttach.Data.Sign(ctx.crypto, kh, ed25519.PublicKey(pubKeyBytes), pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("signing did_doc~attach: %w", err)
		}
	}

	return docAttach, nil
}

func (ctx *context) resolvePublicKey(kid string) ([]byte, error) {
	if strings.HasPrefix(kid, "did:key:") {
		pubKeyBytes, err := fingerprint.PubKeyFromDIDKey(kid)
		if err != nil {
			return nil, fmt.Errorf("failed to extract pubKeyBytes from did:key [%s]: %w", kid, err)
		}

		return pubKeyBytes, nil
	} else if strings.HasPrefix(kid, "did:") {
		vkDID := strings.Split(kid, "#")[0]

		pubDoc, err := ctx.vdRegistry.Resolve(vkDID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve public did for key ID '%s': %w", kid, err)
		}

		vm, ok := did.LookupPublicKey(kid, pubDoc.DIDDocument)
		if !ok {
			return nil, fmt.Errorf("failed to lookup public key for ID %s", kid)
		}

		return vm.Value, nil
	}

	return nil, fmt.Errorf("failed to resolve public key value from kid '%s'", kid)
}

func getPublicDID(options *options) string {
	if options == nil {
		return ""
	}

	return options.publicDID
}

func getRouterConnections(options *options) []string {
	if options == nil {
		return nil
	}

	return options.routerConnections
}

// returns the label given in the options, otherwise an empty string.
func getLabel(options *options) string {
	if options == nil {
		return ""
	}

	return options.label
}

func (ctx *context) getDestination(invitation *Invitation) (*service.Destination, error) {
	if invitation.DID != "" {
		return service.GetDestination(invitation.DID, ctx.vdRegistry)
	}

	accept := ctx.mediaTypeProfiles

	var dest *service.Destination

	if isDIDCommV2(accept) {
		dest = &service.Destination{
			RecipientKeys: invitation.RecipientKeys,
			ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: invitation.ServiceEndpoint, Accept: accept, RoutingKeys: invitation.RoutingKeys},
			}),
		}
	} else {
		dest = &service.Destination{
			RecipientKeys:     invitation.RecipientKeys,
			ServiceEndpoint:   model.NewDIDCommV1Endpoint(invitation.ServiceEndpoint),
			MediaTypeProfiles: accept,
			RoutingKeys:       invitation.RoutingKeys,
		}
	}

	return dest, nil
}

// nolint:gocyclo,funlen
func (ctx *context) getMyDIDDoc(pubDID string, routerConnections []string, serviceType string) (*did.Doc, error) {
	if pubDID != "" {
		logger.Debugf("using public did[%s] for connection", pubDID)

		docResolution, err := ctx.vdRegistry.Resolve(pubDID)
		if err != nil {
			return nil, fmt.Errorf("resolve public did[%s]: %w", pubDID, err)
		}

		err = ctx.connectionStore.SaveDIDFromDoc(docResolution.DIDDocument)
		if err != nil {
			return nil, err
		}

		return docResolution.DIDDocument, nil
	}

	logger.Debugf("creating new '%s' did for connection", didMethod)

	var (
		services   []did.Service
		newService bool
	)

	for _, connID := range routerConnections {
		// get the route configs (pass empty service endpoint, as default service endpoint added in VDR)
		serviceEndpoint, routingKeys, err := mediator.GetRouterConfig(ctx.routeSvc, connID, "")
		if err != nil {
			return nil, fmt.Errorf("did doc - fetch router config: %w", err)
		}

		var svc did.Service

		switch serviceType {
		case didCommServiceType, legacyDIDCommServiceType:
			svc = did.Service{
				Type:            didCommServiceType,
				ServiceEndpoint: model.NewDIDCommV1Endpoint(serviceEndpoint),
				RoutingKeys:     routingKeys,
			}
		case didCommV2ServiceType:
			svc = did.Service{
				Type: didCommV2ServiceType,
				ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
					{URI: serviceEndpoint, RoutingKeys: routingKeys},
				}),
			}
		}

		services = append(services, svc)
	}

	if len(services) == 0 {
		newService = true

		services = append(services, did.Service{Type: serviceType})
	}

	newDID := &did.Doc{Service: services}

	err := ctx.createNewKeyAndVM(newDID)
	if err != nil {
		return nil, fmt.Errorf("failed to create and export public key: %w", err)
	}

	if newService {
		switch didcommutil.GetServiceType(newDID.Service[0].Type) {
		case didCommServiceType, "IndyAgent":
			recKey, _ := fingerprint.CreateDIDKey(newDID.VerificationMethod[0].Value)
			newDID.Service[0].RecipientKeys = []string{recKey}
		case didCommV2ServiceType:
			var recKeys []string

			for _, r := range newDID.KeyAgreement {
				recKeys = append(recKeys, r.VerificationMethod.ID)
			}

			newDID.Service[0].RecipientKeys = recKeys

		default:
			return nil, fmt.Errorf("getMyDIDDoc: invalid DID Doc service type: '%v'", newDID.Service[0].Type)
		}
	}

	// by default use peer did
	docResolution, err := ctx.vdRegistry.Create(didMethod, newDID)
	if err != nil {
		return nil, fmt.Errorf("create %s did: %w", didMethod, err)
	}

	if len(routerConnections) != 0 {
		err = ctx.addRouterKeys(docResolution.DIDDocument, routerConnections)
		if err != nil {
			return nil, err
		}
	}

	err = ctx.connectionStore.SaveDIDFromDoc(docResolution.DIDDocument)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}

func (ctx *context) addRouterKeys(doc *did.Doc, routerConnections []string) error {
	// try DIDComm V2 and use it if found, else use default DIDComm v1 bloc.
	_, ok := did.LookupService(doc, didCommV2ServiceType)
	if ok {
		// use KeyAgreement.ID as recKey for DIDComm V2
		for _, ka := range doc.KeyAgreement {
			for _, connID := range routerConnections {
				// TODO https://github.com/hyperledger/aries-framework-go/issues/1105 Support to Add multiple
				//  recKeys to the Router. (DIDComm V2 uses list of keyAgreements as router keys here, double check
				//  if this issue can be closed).
				kaID := ka.VerificationMethod.ID
				if strings.HasPrefix(kaID, "#") {
					kaID = doc.ID + kaID
				}

				if err := mediator.AddKeyToRouter(ctx.routeSvc, connID, kaID); err != nil {
					return fmt.Errorf("did doc - add key to the router: %w", err)
				}
			}
		}

		return nil
	}

	svc, ok := did.LookupService(doc, didCommServiceType)
	if ok {
		for _, recKey := range svc.RecipientKeys {
			for _, connID := range routerConnections {
				// TODO https://github.com/hyperledger/aries-framework-go/issues/1105 Support to Add multiple
				//  recKeys to the Router
				if err := mediator.AddKeyToRouter(ctx.routeSvc, connID, recKey); err != nil {
					return fmt.Errorf("did doc - add key to the router: %w", err)
				}
			}
		}
	}

	return nil
}

func (ctx *context) isPrivateDIDMethod(method string) bool {
	// todo: find better solution to forcing test dids to be treated as private dids
	if method == "local" || method == "test" {
		return true
	}

	// Interop: treat sov as a peer did: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	return method == "peer" || (ctx.doACAPyInterop && method == "sov")
}

// nolint:gocyclo
func (ctx *context) resolveDidDocFromMessage(didValue string, attachment *decorator.Attachment) (*did.Doc, error) {
	parsedDID, err := did.Parse(didValue)
	// Interop: aca-py dids missing schema:method:, ignore error and skip checking if it's a public did
	// aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if err != nil && !ctx.doACAPyInterop {
		return nil, fmt.Errorf("failed to parse did: %w", err)
	}

	if err == nil && !ctx.isPrivateDIDMethod(parsedDID.Method) {
		docResolution, e := ctx.vdRegistry.Resolve(didValue)
		if e != nil {
			return nil, fmt.Errorf("failed to resolve public did %s: %w", didValue, e)
		}

		return docResolution.DIDDocument, nil
	}

	if attachment == nil {
		return nil, fmt.Errorf("missing did_doc~attach")
	}

	docData, err := attachment.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("failed to parse base64 attachment data: %w", err)
	}

	didDoc, err := did.ParseDocument(docData)
	if err != nil {
		logger.Errorf("failed to parse doc bytes: '%s'", string(docData))

		return nil, fmt.Errorf("failed to parse did document: %w", err)
	}

	// Interop: accommodate aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	var method string

	if parsedDID != nil && parsedDID.Method != "sov" {
		method = parsedDID.Method
	} else {
		method = "peer"
	}

	// Interop: part of above issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if ctx.doACAPyInterop {
		didDoc.ID = didValue
	}

	// store provided did document
	_, err = ctx.vdRegistry.Create(method, didDoc, vdrapi.WithOption("store", true))
	if err != nil {
		return nil, fmt.Errorf("failed to store provided did document: %w", err)
	}

	return didDoc, nil
}

func (ctx *context) handleInboundResponse(response *Response) (stateAction, *connectionstore.Record, error) {
	nsThID, err := connectionstore.CreateNamespaceKey(myNSPrefix, response.Thread.ID)
	if err != nil {
		return nil, nil, err
	}

	connRecord, err := ctx.connectionRecorder.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		return nil, nil, fmt.Errorf("get connection record: %w", err)
	}

	// Interop: aca-py issue https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if ctx.doACAPyInterop && !strings.HasPrefix(response.DID, "did") {
		response.DID = "did:peer:" + response.DID
	}

	connRecord.TheirDID = response.DID

	responseDidDoc, err := ctx.resolveDidDocFromMessage(response.DID, response.DocAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve response did doc: %w", err)
	}

	destination, err := service.CreateDestination(responseDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare destination from response did doc: %w", err)
	}

	docResolution, err := ctx.vdRegistry.Resolve(connRecord.MyDID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching did document: %w", err)
	}

	recKey, err := recipientKey(docResolution.DIDDocument)
	if err != nil {
		return nil, nil, fmt.Errorf("handle inbound response: %w", err)
	}

	completeMsg := &Complete{
		Type: CompleteMsgType,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID:  response.Thread.ID,
			PID: connRecord.ParentThreadID,
		},
	}

	return func() error {
		return ctx.outboundDispatcher.Send(completeMsg, recKey, destination)
	}, connRecord, nil
}

func (ctx *context) getVerKey(invitationID string) (string, error) {
	pubKey, err := ctx.getVerKeyFromOOBInvitation(invitationID)
	if err != nil && !errors.Is(err, errVerKeyNotFound) {
		return "", fmt.Errorf("failed to get my verkey from oob invitation: %w", err)
	}

	if err == nil {
		return pubKey, nil
	}

	var invitation Invitation
	if isDID(invitationID) {
		invitation = Invitation{ID: invitationID, DID: invitationID}
	} else {
		err = ctx.connectionRecorder.GetInvitation(invitationID, &invitation)
		if err != nil {
			return "", fmt.Errorf("get invitation for signature [invitationID=%s]: %w", invitationID, err)
		}
	}

	invPubKey, err := ctx.getInvitationRecipientKey(&invitation)
	if err != nil {
		return "", fmt.Errorf("get invitation recipient key: %w", err)
	}

	return invPubKey, nil
}

func (ctx *context) getInvitationRecipientKey(invitation *Invitation) (string, error) {
	if invitation.DID != "" {
		docResolution, err := ctx.vdRegistry.Resolve(invitation.DID)
		if err != nil {
			return "", fmt.Errorf("get invitation recipient key: %w", err)
		}

		recKey, err := recipientKey(docResolution.DIDDocument)
		if err != nil {
			return "", fmt.Errorf("getInvitationRecipientKey: %w", err)
		}

		return recKey, nil
	}

	return invitation.RecipientKeys[0], nil
}

func (ctx *context) getVerKeyFromOOBInvitation(invitationID string) (string, error) {
	logger.Debugf("invitationID=%s", invitationID)

	var invitation OOBInvitation

	err := ctx.connectionRecorder.GetInvitation(invitationID, &invitation)
	if errors.Is(err, storage.ErrDataNotFound) {
		return "", errVerKeyNotFound
	}

	if err != nil {
		return "", fmt.Errorf("failed to load oob invitation: %w", err)
	}

	if invitation.Type != oobMsgType {
		return "", errVerKeyNotFound
	}

	unmarshalServiceEndpointInOOBTarget(&invitation)

	pubKey, err := ctx.resolveVerKey(&invitation)
	if err != nil {
		return "", fmt.Errorf("failed to get my verkey: %w", err)
	}

	return pubKey, nil
}

//nolint:nestif
func unmarshalServiceEndpointInOOBTarget(invitation *OOBInvitation) {
	// for DIDCommV1, oobInvitation's target serviceEndpoint is a string, transform it to model.Endpoint map equivalent
	// for a successful service decode().
	// for DIDCommV2, transform the target from map[string]interface{} to model.Endpoint
	if targetMap, ok := invitation.Target.(map[string]interface{}); ok {
		if se, ok := targetMap["serviceEndpoint"]; ok {
			seStr, ok := se.(string)
			if ok {
				targetMap["serviceEndpoint"] = model.NewDIDCommV1Endpoint(seStr)
			} else if seMap, ok := se.(map[string]interface{}); ok {
				seStr, ok = seMap["uri"].(string)
				if !ok {
					seStr = ""
				}

				accept, ok := seMap["accept"].([]string)
				if !ok {
					accept = []string{}
				}

				routingKeys, ok := seMap["routingKeys"].([]string)
				if !ok {
					routingKeys = []string{}
				}

				targetMap["serviceEndpoint"] = model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
					{URI: seStr, Accept: accept, RoutingKeys: routingKeys},
				})
			}
		}
	}
}

// nolint:gocyclo,funlen
func (ctx *context) getServiceBlock(i *OOBInvitation) (*did.Service, error) {
	logger.Debugf("extracting service block from oobinvitation=%+v", i)

	var block *did.Service

	switch svc := i.Target.(type) {
	case string:
		docResolution, err := ctx.vdRegistry.Resolve(svc)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve service=%s : %w", svc, err)
		}

		s, found := did.LookupService(docResolution.DIDDocument, didCommV2ServiceType)
		if found {
			// s.recipientKeys are keyAgreement[].VerificationMethod.ID for didComm V2. They are not officially part of
			// the service bloc.
			block = s

			break
		}

		s, found = did.LookupService(docResolution.DIDDocument, didCommServiceType)
		if !found {
			if ctx.doACAPyInterop {
				s, err = interopSovService(docResolution.DIDDocument)
				if err != nil {
					return nil, fmt.Errorf("failed to get interop doc service: %w", err)
				}
			} else {
				return nil, fmt.Errorf(
					"no valid service block found on OOB invitation DID=%s with serviceType=%s",
					svc, didCommServiceType)
			}
		}

		block = s
	case *did.Service:
		block = svc
	case map[string]interface{}:
		var s did.Service

		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: &s})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize decoder : %w", err)
		}

		err = decoder.Decode(svc)
		if err != nil {
			// TODO this error check depend on mapstructure decoding 'ServiceEndpoint' section of service.
			// TODO Find a  better way to build it.
			// for DIDCommV2, decoder.Decode(svc) doesn't support serviceEndpoint as []interface{} representing an array
			// for model.Endpoint. Manually build the endpoint here in this case.
			if strings.Contains(err.Error(), "'serviceEndpoint' expected a map, got 'slice'") {
				extractDIDCommV2EndpointIntoService(svc, &s)
			} else {
				return nil, fmt.Errorf("failed to decode service block : %w", err)
			}
		}

		block = &s
	default:
		return nil, fmt.Errorf("unsupported target type: %+v", svc)
	}

	//nolint:nestif
	if len(i.MediaTypeProfiles) > 0 {
		// marshal/unmarshal to "clone" service block
		blockBytes, err := json.Marshal(block)
		if err != nil {
			return nil, fmt.Errorf("service block marhsal error: %w", err)
		}

		block = &did.Service{}

		err = json.Unmarshal(blockBytes, block)
		if err != nil {
			return nil, fmt.Errorf("service block unmarhsal error: %w", err)
		}

		// updating Accept header requires a cloned service block to avoid Data Race errors.
		// RFC0587: In case the accept property is set in both the DID service block and the out-of-band message,
		// the out-of-band property takes precedence.
		if isDIDCommV2(i.MediaTypeProfiles) {
			block.Type = didCommV2ServiceType

			uri, err := block.ServiceEndpoint.URI()
			if err != nil {
				logger.Debugf("block ServiceEndpoint URI empty for DIDcomm V2, skipping it.")
			}

			routingKeys, err := block.ServiceEndpoint.RoutingKeys()
			if err != nil {
				logger.Debugf("block ServiceEndpoint RoutingKeys empty for DIDcomm V2, skipping these.")
			}

			block.ServiceEndpoint = model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
				{URI: uri, Accept: i.MediaTypeProfiles, RoutingKeys: routingKeys},
			})
		} else {
			block.Type = didCommServiceType
			block.Accept = i.MediaTypeProfiles
		}
	}

	logger.Debugf("extracted service block=%+v", block)

	return block, nil
}

//nolint:gocognit,gocyclo,nestif
func extractDIDCommV2EndpointIntoService(svc map[string]interface{}, s *did.Service) {
	if svcEndpointModel, ok := svc["serviceEndpoint"]; ok {
		if svcEndpointArr, ok := svcEndpointModel.([]interface{}); ok && len(svcEndpointArr) > 0 {
			if svcEndpointMap, ok := svcEndpointArr[0].(map[string]interface{}); ok {
				var (
					uri         string
					accept      []string
					routingKeys []string
				)

				if uriVal, ok := svcEndpointMap["uri"]; ok {
					if uri, ok = uriVal.(string); !ok {
						uri = ""
					}
				}

				if acceptVal, ok := svcEndpointMap["accept"]; ok {
					if acceptArr, ok := acceptVal.([]interface{}); ok {
						for _, a := range acceptArr {
							accept = append(accept, a.(string))
						}
					}
				}

				if routingKeysVal, ok := svcEndpointMap["routingKeys"]; ok {
					if routingKeysArr, ok := routingKeysVal.([]interface{}); ok {
						for _, r := range routingKeysArr {
							routingKeys = append(routingKeys, r.(string))
						}
					}
				}

				s.ServiceEndpoint = model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
					{URI: uri, Accept: accept, RoutingKeys: routingKeys},
				})
			}
		}
	}
}

func isDIDCommV2(mediaTypeProfiles []string) bool {
	for _, mtp := range mediaTypeProfiles {
		switch mtp {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
			return true
		}
	}

	return false
}

func interopSovService(doc *did.Doc) (*did.Service, error) {
	s, found := did.LookupService(doc, "endpoint")
	if !found {
		return nil, fmt.Errorf("no valid service block found on OOB invitation DID=%s with serviceType=%s",
			doc.ID, "endpoint")
	}

	if len(s.RecipientKeys) == 0 {
		for _, vm := range doc.VerificationMethod {
			didKey, _ := fingerprint.CreateDIDKey(vm.Value)

			s.RecipientKeys = append(s.RecipientKeys, didKey)
		}
	}

	return s, nil
}

func (ctx *context) resolveVerKey(i *OOBInvitation) (string, error) {
	logger.Debugf("extracting verkey from oobinvitation=%+v", i)

	svc, err := ctx.getServiceBlock(i)
	if err != nil {
		return "", fmt.Errorf("failed to get service block from oobinvitation : %w", err)
	}

	logger.Debugf("extracted verkey=%s", svc.RecipientKeys[0])

	// use RecipientKeys[0] (DIDComm V1)
	return svc.RecipientKeys[0], nil
}

func isDID(str string) bool {
	const didPrefix = "did:"
	return strings.HasPrefix(str, didPrefix)
}

// returns the did:key ID of the first element in the doc's destination RecipientKeys.
func recipientKey(doc *did.Doc) (string, error) {
	dest, err := service.CreateDestination(doc)
	if err != nil {
		return "", fmt.Errorf("failed to create destination: %w", err)
	}

	return dest.RecipientKeys[0], nil
}

func recipientKeyAsDIDKey(doc *did.Doc) (string, error) {
	var (
		key string
		err error
	)

	serviceType := didcommutil.GetServiceType(doc.Service[0].Type)

	switch serviceType {
	case vdrapi.DIDCommServiceType:
		return recipientKey(doc)
	case vdrapi.DIDCommV2ServiceType:
		// DIDComm V2 recipientKeys are KeyAgreement.ID, convert corresponding verification material to did:key since
		// recipient doesn't have the DID 'doc' yet.
		switch doc.KeyAgreement[0].VerificationMethod.Type {
		case x25519KeyAgreementKey2019:
			key, _ = fingerprint.CreateDIDKeyByCode(fingerprint.X25519PubKeyMultiCodec,
				doc.KeyAgreement[0].VerificationMethod.Value)
		case jsonWebKey2020:
			key, _, err = fingerprint.CreateDIDKeyByJwk(doc.KeyAgreement[0].VerificationMethod.JSONWebKey())
			if err != nil {
				return "", fmt.Errorf("recipientKeyAsDIDKey: unable to create did:key from JWK: %w", err)
			}
		default:
			return "", fmt.Errorf("keyAgreement type '%v' not supported", doc.KeyAgreement[0].VerificationMethod.Type)
		}

		return key, nil
	default:
		return interopRecipientKey(doc)
	}
}
