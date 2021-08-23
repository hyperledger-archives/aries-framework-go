/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
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
	StateIDAbandoned           = "abandoned"
	ackStatusOK                = "ok"
	didCommServiceType         = "did-communication"
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

	// get did document to use in exchange request
	myDIDDoc, err := ctx.getMyDIDDoc(getPublicDID(options), getRouterConnections(options))
	if err != nil {
		return nil, nil, err
	}

	connRec.MyDID = myDIDDoc.ID

	senderKey, err := recipientKey(myDIDDoc)
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

// nolint:gocyclo
func (ctx *context) handleInboundRequest(request *Request, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	logger.Debugf("handling request: %+v", request)

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
	responseDidDoc, err := ctx.getMyDIDDoc(
		getPublicDID(options), getRouterConnections(options))
	if err != nil {
		return nil, nil, fmt.Errorf("get response did doc and connection: %w", err)
	}

	senderVerKey, err := recipientKey(responseDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("handle inbound request: %w", err)
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

	destination, err := service.CreateDestination(requestDidDoc)
	if err != nil {
		return nil, nil, err
	}

	if len(destination.MediaTypeProfiles) > 0 {
		connRec.MediaTypeProfiles = destination.MediaTypeProfiles
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
		signingKID, err := localkms.CreateKID(pubKeyBytes, kms.ED25519Type)
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

	return &service.Destination{
		RecipientKeys:     invitation.RecipientKeys,
		ServiceEndpoint:   invitation.ServiceEndpoint,
		RoutingKeys:       invitation.RoutingKeys,
		MediaTypeProfiles: ctx.mediaTypeProfiles,
	}, nil
}

// nolint:gocyclo,funlen
func (ctx *context) getMyDIDDoc(pubDID string, routerConnections []string) (*did.Doc, error) {
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

	var services []did.Service

	for _, connID := range routerConnections {
		// get the route configs (pass empty service endpoint, as default service endpoint added in VDR)
		serviceEndpoint, routingKeys, err := mediator.GetRouterConfig(ctx.routeSvc, connID, "")
		if err != nil {
			return nil, fmt.Errorf("did doc - fetch router config: %w", err)
		}

		services = append(services, did.Service{ServiceEndpoint: serviceEndpoint, RoutingKeys: routingKeys})
	}

	if len(services) == 0 {
		services = append(services, did.Service{})
	}

	newDID := &did.Doc{Service: services}

	err := createNewKeyAndVM(newDID, ctx.keyType, ctx.keyAgreementType, ctx.kms)
	if err != nil {
		return nil, fmt.Errorf("failed to create and export public key: %w", err)
	}

	// by default use peer did
	docResolution, err := ctx.vdRegistry.Create(didMethod, newDID)
	if err != nil {
		return nil, fmt.Errorf("create %s did: %w", didMethod, err)
	}

	if len(routerConnections) != 0 {
		svc, ok := did.LookupService(docResolution.DIDDocument, didCommServiceType)
		if ok {
			for _, recKey := range svc.RecipientKeys {
				for _, connID := range routerConnections {
					// TODO https://github.com/hyperledger/aries-framework-go/issues/1105 Support to Add multiple
					//  recKeys to the Router
					if err = mediator.AddKeyToRouter(ctx.routeSvc, connID, recKey); err != nil {
						return nil, fmt.Errorf("did doc - add key to the router: %w", err)
					}
				}
			}
		}
	}

	err = ctx.connectionStore.SaveDIDFromDoc(docResolution.DIDDocument)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
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

	pubKey, err := ctx.resolveVerKey(&invitation)
	if err != nil {
		return "", fmt.Errorf("failed to get my verkey: %w", err)
	}

	return pubKey, nil
}

// nolint:gocyclo
func (ctx *context) getServiceBlock(i *OOBInvitation) (*did.Service, error) {
	logger.Debugf("extracting service block from oobinvitation=%+v", i)

	var block *did.Service

	switch svc := i.Target.(type) {
	case string:
		docResolution, err := ctx.vdRegistry.Resolve(svc)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve service=%s : %w", svc, err)
		}

		s, found := did.LookupService(docResolution.DIDDocument, didCommServiceType)
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
			return nil, fmt.Errorf("failed to decode service block : %w", err)
		}

		block = &s
	default:
		return nil, fmt.Errorf("unsupported target type: %+v", svc)
	}

	if len(i.MediaTypeProfiles) > 0 {
		// RFC0587: In case the accept property is set in both the DID service block and the out-of-band message,
		// the out-of-band property takes precedence.
		block.Accept = i.MediaTypeProfiles
	}

	logger.Debugf("extracted service block=%+v", block)

	return block, nil
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
