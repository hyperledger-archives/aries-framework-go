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
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
)

const (
	stateNameNoop      = "noop"
	stateNameNull      = "null"
	stateNameInvited   = "invited"
	stateNameRequested = "requested"
	stateNameResponded = "responded"
	stateNameCompleted = "completed"
	stateNameAbandoned = "abandoned"
	ackStatusOK        = "ok"
	// Todo:How to find the key type -Issue-439
	supportedPublicKeyType = "Ed25519VerificationKey2018"
	serviceType            = "did-communication"
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
	ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *ConnectionRecord,
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
	// TODO: need clarification: noOp state was missing, was it a bug or feature?
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

func (s *noOp) ExecuteInbound(_ *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
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

func (s *null) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
	state, stateAction, error) {
	return &ConnectionRecord{}, &noOp{}, nil, nil
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

func (s *invited) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
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

func (s *requested) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case InvitationMsgType:
		invitation := &Invitation{}

		err := json.Unmarshal(msg.payload, invitation)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unmarshalling failed: %s", err)
		}

		action, connRecord, err := ctx.handleInboundInvitation(invitation, thid, msg.connRecord)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound invitation failed: %s", err)
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

func (s *responded) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case RequestMsgType:
		request := &Request{}

		err := json.Unmarshal(msg.payload, request)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unmarshalling failed: %s", err)
		}

		action, connRecord, err := ctx.handleInboundRequest(request, msg.connRecord)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound request failed: %s", err)
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

func (s *completed) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
	state, stateAction, error) {
	switch msg.header.Type {
	case ResponseMsgType:
		response := &Response{}

		err := json.Unmarshal(msg.payload, response)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unmarshalling failed: %s", err)
		}

		action, connRecord, err := ctx.handleInboundResponse(response)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("handle inbound failed: %s", err)
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

func (s *abandoned) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (*ConnectionRecord,
	state, stateAction, error) {
	return nil, nil, nil, errors.New("not implemented")
}
func (ctx *context) prepareAckConnectionRecord(payload []byte) (*ConnectionRecord, error) {
	ack := &model.Ack{}

	err := json.Unmarshal(payload, ack)
	if err != nil {
		return nil, err
	}

	key, err := createNSKey(theirNSPrefix, ack.Thread.ID)
	if err != nil {
		return nil, err
	}

	return ctx.connectionStore.GetConnectionRecordByNSThreadID(key)
}

func prepareInvitationConnectionRecord(thid string, header *service.Header, payload []byte) (*ConnectionRecord, error) {
	invitation := &Invitation{}

	err := json.Unmarshal(payload, invitation)
	if err != nil {
		return nil, err
	}

	return &ConnectionRecord{
		ConnectionID:    generateRandomID(),
		ThreadID:        thid,
		State:           stateNameNull,
		InvitationID:    invitation.ID,
		ServiceEndPoint: invitation.ServiceEndpoint,
		RecipientKeys:   invitation.RecipientKeys,
		TheirLabel:      invitation.Label,
		Namespace:       findNameSpace(header.Type),
	}, nil
}

func prepareRequestConnectionRecord(payload []byte) (*ConnectionRecord, error) {
	request := Request{}

	err := json.Unmarshal(payload, &request)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %s", err)
	}

	return &ConnectionRecord{
		ConnectionID: generateRandomID(),
		ThreadID:     request.ID,
		State:        stateNameNull,
		TheirDID:     request.Connection.DID,
		Namespace:    theirNSPrefix,
	}, nil
}

func (ctx *context) prepareResponseConnectionRecord(payload []byte) (*ConnectionRecord, error) {
	response := &Response{}

	err := json.Unmarshal(payload, response)
	if err != nil {
		return nil, err
	}

	thid, err := createNSKey(myNSPrefix, response.Thread.ID)
	if err != nil {
		return nil, err
	}

	return ctx.connectionStore.GetConnectionRecordByNSThreadID(thid)
}

func (ctx *context) handleInboundInvitation(invitation *Invitation,
	thid string, connRec *ConnectionRecord) (stateAction, *ConnectionRecord, error) {
	// create a destination from invitation
	destination, err := ctx.getDestination(invitation)
	if err != nil {
		return nil, nil, err
	}

	newDidDoc, err := ctx.didCreator.Create(didMethod)
	if err != nil {
		return nil, nil, err
	}

	err = ctx.didStore.Put(newDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("storing doc in did store: %w", err)
	}

	// prepare the request :
	// TODO Service.Handle() is using the ID from the Invitation as the threadID when instead it should be
	//  using this request's ID. issue-280
	request := &Request{
		Type:  RequestMsgType,
		ID:    thid,
		Label: "",
		Connection: &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		},
	}
	connRec.MyDID = request.Connection.DID

	pubKey, err := getPublicKeys(request.Connection.DIDDoc, supportedPublicKeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("getting public key %s", err)
	}

	return func() error {
		return ctx.outboundDispatcher.Send(request, string(pubKey[0].Value), destination)
	}, connRec, nil
}

func (ctx *context) handleInboundRequest(request *Request, connRec *ConnectionRecord) (stateAction,
	*ConnectionRecord, error) {
	// create a response from Request
	newDidDoc, err := ctx.didCreator.Create(didMethod)
	if err != nil {
		return nil, nil, err
	}

	err = ctx.didStore.Put(newDidDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("storing doc in did store: %w", err)
	}

	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}

	// prepare connection signature
	encodedConnectionSignature, err := ctx.prepareConnectionSignature(connection)
	if err != nil {
		return nil, nil, err
	}

	// prepare the response
	response := &Response{
		Type: ResponseMsgType,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		ConnectionSignature: encodedConnectionSignature,
	}

	connRec.TheirDID = request.Connection.DID
	connRec.MyDID = connection.DID
	destination := prepareDestination(request.Connection.DIDDoc)

	pubKey, err := getPublicKeys(connection.DIDDoc, supportedPublicKeyType)
	if err != nil {
		return nil, nil, err
	}

	// send exchange response
	return func() error {
		return ctx.outboundDispatcher.Send(response, string(pubKey[0].Value), destination)
	}, connRec, nil
}

func (ctx *context) getDestination(invitation *Invitation) (*service.Destination, error) {
	if invitation.DID != "" {
		return ctx.getDestinationFromDID(invitation.DID)
	}

	return &service.Destination{
		RecipientKeys:   invitation.RecipientKeys,
		ServiceEndpoint: invitation.ServiceEndpoint,
		RoutingKeys:     invitation.RoutingKeys,
	}, nil
}

func (ctx *context) getDestinationFromDID(id string) (*service.Destination, error) {
	didDoc, err := ctx.didResolver.Resolve(id)
	if err != nil {
		return nil, err
	}

	pubKeys, err := getPublicKeys(didDoc, supportedPublicKeyType)
	if err != nil {
		return nil, err
	}

	recepientKey := string(pubKeys[0].Value)

	serviceEndpoint, err := getServiceEndpoint(didDoc)
	if err != nil {
		return nil, err
	}

	return &service.Destination{
		RecipientKeys:   []string{recepientKey},
		ServiceEndpoint: serviceEndpoint,
		RoutingKeys:     []string{recepientKey},
	}, nil
}

func getServiceEndpoint(didDoc *did.Doc) (string, error) {
	for _, s := range didDoc.Service {
		if s.Type == serviceType {
			return s.ServiceEndpoint, nil
		}
	}

	return "", errors.New("service not found in DID document")
}

// TODO: Need to figure out how to find the destination for outbound request
//  https://github.com/hyperledger/aries-framework-go/issues/282
func prepareDestination(didDoc *did.Doc) *service.Destination {
	var srvEndPoint string
	for _, v := range didDoc.Service {
		srvEndPoint = v.ServiceEndpoint
	}

	pubKey := didDoc.PublicKey

	recipientKeys := make([]string, len(pubKey))
	for i, v := range pubKey {
		recipientKeys[i] = string(v.Value)
	}

	return &service.Destination{
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: srvEndPoint,
	}
}

// Encode the connection and convert to Connection Signature as per the spec:
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange
func (ctx *context) prepareConnectionSignature(connection *Connection) (*ConnectionSignature, error) {
	connAttributeBytes, err := json.Marshal(connection)
	if err != nil {
		return nil, err
	}

	now := getEpochTime()
	timestamp := strconv.FormatInt(now, 10)
	prefix := append([]byte(timestamp), signatureDataDelimiter)
	concatenateSignData := append(prefix, connAttributeBytes...)

	// TODO: As per spec we should sign using recipientKeys - this will be done upon completing issue-625
	// that allows for correlation between exchange-request and invitation using pthid
	pubKey := string(connection.DIDDoc.PublicKey[0].Value)

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
func (ctx *context) handleInboundResponse(response *Response) (stateAction, *ConnectionRecord, error) {
	ack := &model.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Status: ackStatusOK,
		Thread: &decorator.Thread{
			ID: response.Thread.ID,
		},
	}

	conn, err := verifySignature(response.ConnectionSignature)
	if err != nil {
		return nil, nil, err
	}

	nsThID, err := createNSKey(myNSPrefix, ack.Thread.ID)
	if err != nil {
		return nil, nil, err
	}

	connRecord, err := ctx.connectionStore.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		return nil, nil, fmt.Errorf("get connection record: %w", err)
	}

	connRecord.TheirDID = conn.DID
	destination := prepareDestination(conn.DIDDoc)

	myDidDoc, err := ctx.didResolver.Resolve(connRecord.MyDID)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching did document: %w", err)
	}

	pubKey, err := getPublicKeys(myDidDoc, supportedPublicKeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("get public keys: %w", err)
	}

	return func() error {
		return ctx.outboundDispatcher.Send(ack, string(pubKey[0].Value), destination)
	}, connRecord, nil
}

// verifySignature verifies connection signature and returns connection
func verifySignature(connSignature *ConnectionSignature) (*Connection, error) {
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

	// TODO: As per spec inviter should sign using recipientKeys - this will be done upon completing issue-625
	// The signature data must be used to verify against the invitation's recipientKeys for continuity.
	pubKey, err := base64.URLEncoding.DecodeString(connSignature.SignVerKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

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
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	return conn, nil
}

func getEpochTime() int64 {
	return time.Now().Unix()
}

func getPublicKeys(didDoc *did.Doc, pubKeyType string) ([]did.PublicKey, error) {
	var publicKeys []did.PublicKey

	for k, pubKey := range didDoc.PublicKey {
		if pubKey.Type == pubKeyType {
			publicKeys = append(publicKeys, didDoc.PublicKey[k])
		}
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("public key not supported")
	}

	return publicKeys, nil
}
