/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	model2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/didcommutil"
	"github.com/hyperledger/aries-framework-go/pkg/internal/didkeyutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	connectionstore "github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	stateNameNoop = "noop"
	stateNameNull = "null"
	// StateIDInvited marks the invited phase of the connection protocol.
	StateIDInvited = "invited"
	// StateIDRequested marks the requested phase of the connection protocol.
	StateIDRequested = "requested"
	// StateIDResponded marks the responded phase of the connection protocol.
	StateIDResponded = "responded"
	// StateIDCompleted marks the completed phase of the connection protocol.
	StateIDCompleted   = "completed"
	didCommServiceType = "did-communication"
	ackStatusOK        = "ok"
	// legacyDIDCommServiceType for aca-py interop.
	legacyDIDCommServiceType   = "IndyAgent"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	didMethod                  = "peer"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	signatureType              = "https://didcomm.org/signature/1.0/ed25519Sha512_single"
	// PlsAckOnReceipt ack type that says, "Please send me an ack as soon as you receive this message.".
	PlsAckOnReceipt = "RECEIPT"
	timestampLength = 8
)

// state action for network call.
type stateAction func() error

// The connection protocol's state.
type state interface {
	// Name of this state.
	Name() string

	// CanTransitionTo Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool

	// ExecuteInbound this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record,
		state state, action stateAction, err error)
}

// Returns the state towards which the protocol will transition to if the msgType is processed.
func stateFromMsgType(msgType string) (state, error) {
	switch msgType {
	case InvitationMsgType:
		return &invited{}, nil
	case RequestMsgType:
		return &requested{}, nil
	case ResponseMsgType:
		return &responded{}, nil
	case AckMsgType:
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

func (s *noOp) ExecuteInbound(_ *stateMachineMsg, _ string, _ *context) (*connectionstore.Record,
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

func (s *null) ExecuteInbound(_ *stateMachineMsg, _ string, _ *context) (*connectionstore.Record,
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
	if msg.Type() != InvitationMsgType {
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

func (s *responded) ExecuteInbound(msg *stateMachineMsg, _ string, ctx *context) (*connectionstore.Record,
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
	case ResponseMsgType:
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

func (s *completed) CanTransitionTo(_ state) bool {
	return false
}

func (s *completed) ExecuteInbound(msg *stateMachineMsg, _ string, ctx *context) (*connectionstore.Record,
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
	default:
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}
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

	return ctx.createConnectionRequest(destination, getLabel(options), thid, pid, options, connRec)
}

func (ctx *context) createConnectionRequest(destination *service.Destination, label, thid, pthid string,
	options *options, connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	request := &Request{
		Type:  RequestMsgType,
		ID:    thid,
		Label: label,
		Thread: &decorator.Thread{
			PID: pthid,
		},
	}
	// get did document to use in connection request
	myDIDDoc, err := ctx.getMyDIDDoc(getPublicDID(options), getRouterConnections(options), legacyDIDCommServiceType)
	if err != nil {
		return nil, nil, err
	}

	connRec.MyDID = myDIDDoc.ID

	senderKey, err := recipientKey(myDIDDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("getting recipient key: %w", err)
	}

	request.Connection = &Connection{
		DID:    myDIDDoc.ID,
		DIDDoc: myDIDDoc,
	}

	return func() error {
		return ctx.outboundDispatcher.Send(request, senderKey, destination)
	}, connRec, nil
}

// nolint:gocyclo,funlen
func (ctx *context) handleInboundRequest(request *Request, options *options,
	connRec *connectionstore.Record) (stateAction, *connectionstore.Record, error) {
	logger.Debugf("handling request: %#v", request)

	requestDidDoc, err := ctx.resolveDidDocFromConnection(request.Connection)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve did doc from connection request: %w", err)
	}

	// get did document that will be used in connection response
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
		serviceType = legacyDIDCommServiceType
	}

	responseDidDoc, err := ctx.getMyDIDDoc(myDID, getRouterConnections(options), serviceType)
	if err != nil {
		return nil, nil, fmt.Errorf("get response did doc and connection: %w", err)
	}

	var verKey string
	if len(connRec.InvitationRecipientKeys) > 0 {
		verKey = connRec.InvitationRecipientKeys[0]
	} else {
		verKey, err = ctx.getVerKey(request.Thread.PID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get verkey : %w", err)
		}
	}

	// prepare connection signature
	connectionSignature, err := ctx.prepareConnectionSignature(responseDidDoc, verKey)
	if err != nil {
		return nil, nil, err
	}

	response := ctx.prepareResponse(request, connectionSignature)

	var senderVerKey string

	senderVerKey, err = recipientKey(responseDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("get recipient key: %w", err)
	}

	connRec.MyDID = responseDidDoc.ID
	connRec.TheirDID = request.Connection.DID
	connRec.TheirLabel = request.Label

	if len(responseDidDoc.Service) > 0 {
		connRec.RecipientKeys = responseDidDoc.Service[0].RecipientKeys
	}

	accept, err := destination.ServiceEndpoint.Accept()
	if err != nil {
		accept = []string{}
	}

	if len(accept) > 0 {
		connRec.MediaTypeProfiles = accept
	}
	// send connection response
	return func() error {
		return ctx.outboundDispatcher.Send(response, senderVerKey, destination)
	}, connRec, nil
}

func (ctx *context) prepareConnectionSignature(didDoc *did.Doc, verKey string) (*ConnectionSignature, error) {
	connection := &Connection{
		DID:    didDoc.ID,
		DIDDoc: didDoc,
	}
	logger.Debugf("connection=%+v verKey=%s", connection, verKey)

	connAttributeBytes, err := connection.toLegacyJSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal connection : %w", err)
	}

	now := time.Now().Unix()
	timestampBuf := make([]byte, timestampLength)
	binary.BigEndian.PutUint64(timestampBuf, uint64(now))

	concatenateSignData := append(timestampBuf, connAttributeBytes...)

	var signingKey []byte

	if strings.HasPrefix(verKey, "did:key:") {
		var pubKey *crypto.PublicKey

		pubKey, err = kmsdidkey.EncryptionPubKeyFromDIDKey(verKey)
		if err != nil {
			return nil, err
		}

		signingKey = pubKey.X
	} else {
		signingKey = base58.Decode(verKey)
	}

	signingKID, err := jwkkid.CreateKID(signingKey, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KID from public key: %w", err)
	}

	kh, err := ctx.kms.Get(signingKID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key handle: %w", err)
	}

	var signature []byte

	signature, err = ctx.crypto.Sign(concatenateSignData, kh)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return &ConnectionSignature{
		Type:       signatureType,
		SignedData: base64.URLEncoding.EncodeToString(concatenateSignData),
		SignVerKey: verKey,
		Signature:  base64.URLEncoding.EncodeToString(signature),
	}, nil
}

func (ctx *context) prepareResponse(request *Request, signature *ConnectionSignature) *Response {
	// prepare the response
	response := &Response{
		Type: ResponseMsgType,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		ConnectionSignature: signature,
		PleaseAck: &PleaseAck{
			[]string{PlsAckOnReceipt},
		},
	}

	if request.Thread != nil {
		response.Thread.PID = request.Thread.PID
	}

	return response
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
	if isDIDCommV2(accept) {
		return nil, fmt.Errorf("DIDComm V2 profile type(s): %v - are not supported", accept)
	}

	return &service.Destination{
		RecipientKeys:     invitation.RecipientKeys,
		ServiceEndpoint:   model.NewDIDCommV1Endpoint(invitation.ServiceEndpoint),
		MediaTypeProfiles: accept,
		RoutingKeys:       invitation.RoutingKeys,
	}, nil
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
			routingKeys = didkeyutil.ConvertDIDKeysToBase58Keys(routingKeys)
			svc = did.Service{
				Type:            serviceType,
				ServiceEndpoint: model.NewDIDCommV1Endpoint(serviceEndpoint),
				RoutingKeys:     routingKeys,
			}
		default:
			return nil, fmt.Errorf("service type %s is not supported", serviceType)
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
		case didCommServiceType, legacyDIDCommServiceType:
			newDID.Service[0].RecipientKeys = []string{base58.Encode(newDID.VerificationMethod[0].Value)}
		default:
			return nil, fmt.Errorf("service type %s is not supported", newDID.Service[0].Type)
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
	svc, ok := did.LookupService(doc, legacyDIDCommServiceType)
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

	return method == "peer" || method == "sov" || method == "key"
}

func (ctx *context) resolveDidDocFromConnection(con *Connection) (*did.Doc, error) {
	if con.DIDDoc == nil {
		return nil, fmt.Errorf("missing DIDDoc")
	}
	// FIXME Interop: aca-py and vcx issue. Should be removed after theirs fix
	if !strings.HasPrefix(con.DIDDoc.ID, "did") && len(con.DIDDoc.Service) > 0 {
		if len(con.DIDDoc.Service[0].RecipientKeys) > 0 {
			con.DIDDoc.ID = didkeyutil.ConvertBase58KeysToDIDKeys(con.DIDDoc.Service[0].RecipientKeys)[0]
			con.DID = con.DIDDoc.ID
		}
	}

	parsedDID, err := did.Parse(con.DID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did: %w", err)
	}

	if err == nil && !ctx.isPrivateDIDMethod(parsedDID.Method) {
		docResolution, e := ctx.vdRegistry.Resolve(con.DID)
		if e != nil {
			return nil, fmt.Errorf("failed to resolve public did %s: %w", con.DID, e)
		}

		return docResolution.DIDDocument, nil
	}
	// store provided did document
	_, err = ctx.vdRegistry.Create("peer", con.DIDDoc, vdrapi.WithOption("store", true))
	if err != nil {
		return nil, fmt.Errorf("failed to store provided did document: %w", err)
	}

	return con.DIDDoc, nil
}

func (ctx *context) handleInboundResponse(response *Response) (stateAction, *connectionstore.Record, error) {
	ack := model2.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Status: ackStatusOK,
		Thread: &decorator.Thread{
			ID: response.Thread.ID,
		},
	}

	nsThID, err := connectionstore.CreateNamespaceKey(myNSPrefix, ack.Thread.ID)
	if err != nil {
		return nil, nil, err
	}

	connRecord, err := ctx.connectionRecorder.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		return nil, nil, fmt.Errorf("get connection record: %w", err)
	}

	conn, err := ctx.verifySignature(response.ConnectionSignature, connRecord.RecipientKeys[0])
	if err != nil {
		return nil, nil, err
	}

	connRecord.TheirDID = conn.DID

	responseDidDoc, err := ctx.resolveDidDocFromConnection(conn)
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

	return func() error {
		return ctx.outboundDispatcher.Send(ack, recKey, destination)
	}, connRecord, nil
}

// verifySignature verifies connection signature and returns connection.
func (ctx *context) verifySignature(connSignature *ConnectionSignature, recipientKeys string) (*Connection, error) {
	sigData, err := base64.URLEncoding.DecodeString(connSignature.SignedData)
	if err != nil {
		return nil, fmt.Errorf("decode signature data: %w", err)
	}

	if len(sigData) == 0 {
		return nil, fmt.Errorf("missing or invalid signature data")
	}

	signature, err := base64.URLEncoding.DecodeString(connSignature.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	// The signature data must be used to verify against the invitation's recipientKeys for continuity.
	var verKey []byte

	if strings.HasPrefix(recipientKeys, "did:key:") {
		var pubKey *crypto.PublicKey

		pubKey, err = kmsdidkey.EncryptionPubKeyFromDIDKey(recipientKeys)
		if err != nil {
			return nil, err
		}

		verKey = pubKey.X
	} else {
		verKey = base58.Decode(recipientKeys)
	}

	kh, err := ctx.kms.PubKeyBytesToHandle(verKey, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("failed to get key handle: %w", err)
	}

	err = ctx.crypto.Verify(signature, sigData, kh)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	// trimming the timestamp and delimiter - only taking out connection attribute bytes
	if len(sigData) <= timestampLength {
		return nil, fmt.Errorf("missing connection attribute bytes")
	}

	connBytes := sigData[timestampLength:]

	conn, err := parseLegacyJSONBytes(connBytes)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of connection: %w", err)
	}

	return conn, nil
}

func (ctx *context) getVerKey(invitationID string) (string, error) {
	var invitation Invitation

	if isDID(invitationID) {
		invitation = Invitation{ID: invitationID, DID: invitationID}
	} else {
		err := ctx.connectionRecorder.GetInvitation(invitationID, &invitation)
		if err != nil {
			return "", fmt.Errorf("get invitation for [invitationID=%s]: %w", invitationID, err)
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

func isDID(str string) bool {
	const didPrefix = "did:"
	return strings.HasPrefix(str, didPrefix)
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

// returns the did:key ID of the first element in the doc's destination RecipientKeys.
func recipientKey(doc *did.Doc) (string, error) {
	serviceType := didcommutil.GetServiceType(doc.Service[0].Type)

	switch serviceType {
	case vdrapi.DIDCommServiceType, legacyDIDCommServiceType:
		dest, err := service.CreateDestination(doc)
		if err != nil {
			return "", fmt.Errorf("failed to create destination: %w", err)
		}

		return dest.RecipientKeys[0], nil
	default:
		return "", fmt.Errorf("recipientKeyAsDIDKey: invalid DID Doc service type: '%v'", doc.Service[0].Type)
	}
}
