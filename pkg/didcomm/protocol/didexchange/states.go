/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
)

const (
	stateNameNoop          = "noop"
	stateNameNull          = "null"
	stateNameInvited       = "invited"
	stateNameRequested     = "requested"
	stateNameResponded     = "responded"
	stateNameCompleted     = "completed"
	stateNameAbandoned     = "abandoned"
	ackStatusOK            = "ok"
	ed25519KeyType         = "Ed25519VerificationKey2018"
	didCommServiceType     = "did-communication"
	didMethod              = "peer"
	signatureDataDelimiter = '|'
)

// state action for network call
type stateAction func() error

// The did-exchange protocol's state.
type state interface {
	// Name of this state.
	Name() string

	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool

	// ExecuteInbound this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.ConnectionRecord,
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
	case stateNameInvited:
		return &invited{}, nil
	case stateNameRequested:
		return &requested{}, nil
	case stateNameResponded:
		return &responded{}, nil
	case stateNameCompleted:
		return &completed{}, nil
	case stateNameAbandoned:
		return &abandoned{}, nil
	default:
		return nil, fmt.Errorf("invalid state name %s", name)
	}
}

type noOp struct {
}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	return nil, nil, nil, errors.New("cannot execute no-op")
}

// null state
type null struct {
}

func (s *null) Name() string {
	return stateNameNull
}

func (s *null) CanTransitionTo(next state) bool {
	return stateNameInvited == next.Name() || stateNameRequested == next.Name()
}

func (s *null) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	return &connectionstore.ConnectionRecord{}, &noOp{}, nil, nil
}

// invited state
type invited struct {
}

func (s *invited) Name() string {
	return stateNameInvited
}

func (s *invited) CanTransitionTo(next state) bool {
	return stateNameRequested == next.Name()
}

func (s *invited) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	if msg.header.Type != InvitationMsgType {
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.header.Type, s.Name())
	}

	msg.connRecord.ThreadID = thid

	return msg.connRecord, &requested{}, func() error { return nil }, nil
}

// requested state
type requested struct {
}

func (s *requested) Name() string {
	return stateNameRequested
}

func (s *requested) CanTransitionTo(next state) bool {
	return stateNameResponded == next.Name()
}

func (s *requested) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case InvitationMsgType:
		invitation := &Invitation{}

		err := json.Unmarshal(msg.payload, invitation)
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
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.header.Type, s.Name())
	}
}

// responded state
type responded struct {
}

func (s *responded) Name() string {
	return stateNameResponded
}

func (s *responded) CanTransitionTo(next state) bool {
	return stateNameCompleted == next.Name()
}

func (s *responded) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case RequestMsgType:
		request := &Request{}

		err := json.Unmarshal(msg.payload, request)
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
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.header.Type, s.Name())
	}
}

// completed state
type completed struct {
}

func (s *completed) Name() string {
	return stateNameCompleted
}

func (s *completed) CanTransitionTo(next state) bool {
	return false
}

func (s *completed) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case ResponseMsgType:
		response := &Response{}

		err := json.Unmarshal(msg.payload, response)
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
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.header.Type, s.Name())
	}
}

// abandoned state
type abandoned struct {
}

func (s *abandoned) Name() string {
	return stateNameAbandoned
}

func (s *abandoned) CanTransitionTo(next state) bool {
	return false
}

func (s *abandoned) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*connectionstore.ConnectionRecord,
	state, stateAction, error) {
	return nil, nil, nil, errors.New("not implemented")
}

func (ctx *context) handleInboundInvitation(invitation *Invitation, thid string, options *options,
	connRec *connectionstore.ConnectionRecord) (stateAction, *connectionstore.ConnectionRecord, error) {
	// create a destination from invitation
	destination, err := ctx.getDestination(invitation)
	if err != nil {
		return nil, nil, err
	}

	// get did document that will be used in exchange request
	didDoc, conn, err := ctx.getDIDDocAndConnection(getPublicDID(options))
	if err != nil {
		return nil, nil, err
	}

	pid := invitation.ID
	if connRec.Implicit {
		pid = invitation.DID
	}

	request := &Request{
		Header: service.Header{
			ID: thid,
			Thread: &decorator.Thread{
				PID: pid,
			},
			Type: RequestMsgType,
		},
		Label:      getLabel(options),
		Connection: conn,
	}
	connRec.MyDID = request.Connection.DID

	senderVerKeys, ok := did.LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
	if !ok {
		return nil, nil, fmt.Errorf("getting sender verification keys")
	}

	return func() error {
		return ctx.outboundDispatcher.Send(request, senderVerKeys[0], destination)
	}, connRec, nil
}

func (ctx *context) handleInboundRequest(request *Request, options *options,
	connRec *connectionstore.ConnectionRecord) (stateAction, *connectionstore.ConnectionRecord, error) {
	requestDidDoc, err := ctx.resolveDidDocFromConnection(request.Connection)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve did doc from exchange request connection: %w", err)
	}

	// get did document that will be used in exchange response
	// (my did doc)
	responseDidDoc, connection, err := ctx.getDIDDocAndConnection(getPublicDID(options))
	if err != nil {
		return nil, nil, err
	}

	// prepare connection signature
	encodedConnectionSignature, err := ctx.prepareConnectionSignature(connection, request.Thread.PID)
	if err != nil {
		return nil, nil, err
	}

	// prepare the response
	response := &Response{
		Header: service.Header{
			ID: uuid.New().String(),
			Thread: &decorator.Thread{
				ID: request.ID,
			},
			Type: ResponseMsgType,
		},
		ConnectionSignature: encodedConnectionSignature,
	}

	connRec.TheirDID = request.Connection.DID
	connRec.MyDID = connection.DID
	connRec.TheirLabel = request.Label

	destination, err := service.CreateDestination(requestDidDoc)
	if err != nil {
		return nil, nil, err
	}

	senderVerKeys, ok := did.LookupRecipientKeys(responseDidDoc, didCommServiceType, ed25519KeyType)
	if !ok {
		return nil, nil, fmt.Errorf("getting sender verification keys")
	}

	// send exchange response
	return func() error {
		return ctx.outboundDispatcher.Send(response, senderVerKeys[0], destination)
	}, connRec, nil
}

func getPublicDID(options *options) string {
	if options == nil {
		return ""
	}

	return options.publicDID
}

func getLabel(options *options) string {
	if options == nil {
		return ""
	}

	return options.label
}

func (ctx *context) getDestination(invitation *Invitation) (*service.Destination, error) {
	if invitation.DID != "" {
		return service.GetDestination(invitation.DID, ctx.vdriRegistry)
	}

	return &service.Destination{
		RecipientKeys:   invitation.RecipientKeys,
		ServiceEndpoint: invitation.ServiceEndpoint,
		RoutingKeys:     invitation.RoutingKeys,
	}, nil
}

func (ctx *context) getDIDDocAndConnection(pubDID string) (*did.Doc, *Connection, error) {
	if pubDID != "" {
		logger.Debugf("using public did[%s] for connection", pubDID)

		didDoc, err := ctx.vdriRegistry.Resolve(pubDID)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve public did[%s]: %w", pubDID, err)
		}

		err = ctx.connectionStore.didStore.SaveDIDFromDoc(didDoc)
		if err != nil {
			return nil, nil, err
		}

		return didDoc, &Connection{DID: didDoc.ID}, nil
	}

	logger.Debugf("creating new '%s' did for connection", didMethod)

	// by default use peer did
	newDidDoc, err := ctx.vdriRegistry.Create(didMethod)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s did: %w", didMethod, err)
	}

	err = ctx.connectionStore.didStore.SaveDIDFromDoc(newDidDoc)
	if err != nil {
		return nil, nil, err
	}

	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}

	return newDidDoc, connection, nil
}

func (ctx *context) resolveDidDocFromConnection(conn *Connection) (*did.Doc, error) {
	didDoc := conn.DIDDoc
	if didDoc == nil {
		// did content was not provided; resolve
		return ctx.vdriRegistry.Resolve(conn.DID)
	}

	// store provided did document
	err := ctx.vdriRegistry.Store(didDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to store provided did document: %w", err)
	}

	return didDoc, nil
}

// Encode the connection and convert to Connection Signature as per the spec:
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange
func (ctx *context) prepareConnectionSignature(connection *Connection,
	invitationID string) (*ConnectionSignature, error) {
	connAttributeBytes, err := json.Marshal(connection)
	if err != nil {
		return nil, err
	}

	now := getEpochTime()
	timestamp := strconv.FormatInt(now, 10)
	prefix := append([]byte(timestamp), signatureDataDelimiter)
	concatenateSignData := append(prefix, connAttributeBytes...)

	var invitation *Invitation
	if isDID(invitationID) {
		invitation = &Invitation{
			Header: service.Header{
				ID: invitationID,
			},
			DID: invitationID,
		}
	} else {
		invitation, err = ctx.connectionStore.GetInvitation(invitationID)
		if err != nil {
			return nil, fmt.Errorf("get invitation for signature: %w", err)
		}
	}

	pubKey, err := ctx.getInvitationRecipientKey(invitation)
	if err != nil {
		return nil, fmt.Errorf("get invitation recipient key: %w", err)
	}

	// TODO: Replace with signed attachments issue-626
	signature, err := ctx.signer.SignMessage(concatenateSignData, pubKey)
	if err != nil {
		return nil, fmt.Errorf("sign response message: %w", err)
	}

	return &ConnectionSignature{
		Type:       "https://didcomm.org/signature/1.0/ed25519Sha512_single",
		SignedData: base64.URLEncoding.EncodeToString(concatenateSignData),
		SignVerKey: base64.URLEncoding.EncodeToString(base58.Decode(pubKey)),
		Signature:  base64.URLEncoding.EncodeToString(signature),
	}, nil
}

func (ctx *context) handleInboundResponse(response *Response) (stateAction, *connectionstore.ConnectionRecord, error) {
	ack := &model.Ack{
		Header: service.Header{
			ID: uuid.New().String(),
			Thread: &decorator.Thread{
				ID: response.Thread.ID,
			},
			Type: AckMsgType,
		},
		Status: ackStatusOK,
	}
	nsThID, err := createNSKey(myNSPrefix, ack.Thread.ID)

	if err != nil {
		return nil, nil, err
	}

	connRecord, err := ctx.connectionStore.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		return nil, nil, fmt.Errorf("get connection record: %w", err)
	}

	conn, err := verifySignature(response.ConnectionSignature, connRecord.RecipientKeys[0])

	if err != nil {
		return nil, nil, err
	}

	connRecord.TheirDID = conn.DID

	responseDidDoc, err := ctx.resolveDidDocFromConnection(conn)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve did doc from exchange response connection: %w", err)
	}

	destination, err := service.CreateDestination(responseDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare destination from response did doc: %w", err)
	}

	myDidDoc, err := ctx.vdriRegistry.Resolve(connRecord.MyDID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching did document: %w", err)
	}

	senderVerKeys, ok := did.LookupRecipientKeys(myDidDoc, didCommServiceType, ed25519KeyType)
	if !ok {
		return nil, nil, fmt.Errorf("getting sender verification keys")
	}

	return func() error {
		return ctx.outboundDispatcher.Send(ack, senderVerKeys[0], destination)
	}, connRecord, nil
}

// verifySignature verifies connection signature and returns connection
func verifySignature(connSignature *ConnectionSignature, recipientKeys string) (*Connection, error) {
	sigData, err := base64.URLEncoding.DecodeString(connSignature.SignedData)
	if err != nil {
		return nil, fmt.Errorf("decode signature data: %w", err)
	}

	if len(sigData) == 0 || !bytes.ContainsRune(sigData, signatureDataDelimiter) {
		return nil, fmt.Errorf("missing or invalid signature data")
	}

	signature, err := base64.URLEncoding.DecodeString(connSignature.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	// The signature data must be used to verify against the invitation's recipientKeys for continuity.
	pubKey := base58.Decode(recipientKeys)

	// TODO: Replace with signed attachments issue-626
	signatureSuite := ed25519signature2018.New()

	err = signatureSuite.Verify(pubKey, sigData, signature)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	// trimming the timestamp and delimiter - only taking out connection attribute bytes
	connectionIndex := bytes.IndexRune(sigData, signatureDataDelimiter) + 1
	if connectionIndex >= len(sigData) {
		return nil, fmt.Errorf("missing connection attribute bytes")
	}

	connBytes := sigData[connectionIndex:]
	conn := &Connection{}

	err = json.Unmarshal(connBytes, conn)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of connection: %w", err)
	}

	return conn, nil
}

func getEpochTime() int64 {
	return time.Now().Unix()
}

func (ctx *context) getInvitationRecipientKey(invitation *Invitation) (string, error) {
	if invitation.DID != "" {
		didDoc, err := ctx.vdriRegistry.Resolve(invitation.DID)
		if err != nil {
			return "", fmt.Errorf("get invitation recipient key: %w", err)
		}

		recipientKeys, ok := did.LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		if !ok {
			return "", fmt.Errorf("get recipient keys from did")
		}

		return recipientKeys[0], nil
	}

	return invitation.RecipientKeys[0], nil
}

func isDID(str string) bool {
	const didPrefix = "did:"
	return strings.HasPrefix(str, didPrefix)
}
