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

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	stateNameNoop      = "noop"
	stateNameNull      = "null"
	stateNameInvited   = "invited"
	stateNameRequested = "requested"
	stateNameResponded = "responded"
	stateNameCompleted = "completed"
	ackStatusOK        = "ok"
)

//TODO: This is temporary to move forward with bdd test will be fixed in Issue-353
var temp string //nolint
// The did-exchange protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (followup state, err error)
}

// Returns the state towards which the protocol will transition to if the msgType is processed.
func stateFromMsgType(msgType string) (state, error) {
	switch msgType {
	case ConnectionInvite:
		return &invited{}, nil
	case ConnectionRequest:
		return &requested{}, nil
	case ConnectionResponse:
		return &responded{}, nil
	case ConnectionAck:
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

func (s *noOp) Execute(_ dispatcher.DIDCommMsg, thid string, ctx context) (state, error) {
	return nil, errors.New("cannot execute no-op")
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

func (s *null) Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (state, error) {
	return &noOp{}, nil
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

func (s *invited) Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (state, error) {
	if msg.Type != ConnectionInvite {
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
	if msg.Outbound {
		// illegal
		return nil, errors.New("outbound invitations are not allowed")
	}
	return &requested{}, nil
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

func (s *requested) Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (state, error) { //nolint:dupl
	switch msg.Type {
	case ConnectionInvite:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound invitations are not allowed for state %s", s.Name())
		}
		invitation := &Invitation{}
		err := json.Unmarshal(msg.Payload, invitation)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling failed: %s", err)
		}
		err = ctx.handleInboundInvitation(invitation, thid)
		if err != nil {
			return nil, fmt.Errorf("handle inbound invitation failed: %s", err)
		}
		return &noOp{}, nil
	case ConnectionRequest:
		if msg.Outbound {
			err := ctx.sendOutboundRequest(msg)
			if err != nil {
				return nil, fmt.Errorf("send outbound request failed: %s", err)
			}
			return &noOp{}, nil
		}
		return &responded{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
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

func (s *responded) Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (state, error) { //nolint:dupl
	switch msg.Type {
	case ConnectionRequest:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound requests are not allowed for state %s", s.Name())
		}
		request := &Request{}
		err := json.Unmarshal(msg.Payload, request)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling failed: %s", err)
		}
		err = ctx.handleInboundRequest(request)
		if err != nil {
			return nil, fmt.Errorf("handle inbound request failed: %s", err)
		}
		return &noOp{}, nil
	case ConnectionResponse:
		if msg.Outbound {
			err := ctx.sendOutboundResponse(msg)
			if err != nil {
				return nil, fmt.Errorf("send outbound response failed: %s", err)
			}
			return &noOp{}, nil
		}
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
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

func (s *completed) Execute(msg dispatcher.DIDCommMsg, thid string, ctx context) (state, error) {
	switch msg.Type {
	case ConnectionResponse:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound responses are not allowed for state %s", s.Name())
		}
		response := &Response{}
		err := json.Unmarshal(msg.Payload, response)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling failed: %s", err)
		}
		err = ctx.handleInboundResponse(response)
		if err != nil {
			return nil, fmt.Errorf("handle inbound failed: %s", err)
		}
		return &noOp{}, nil
	case ConnectionAck:
		if msg.Outbound {
			err := ctx.sendOutboundAck(msg)
			if err != nil {
				return nil, fmt.Errorf("send outbound ack failed: %s", err)
			}
		}
		//TODO: issue-333 otherwise save did-exchange connection
		return &noOp{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
}
func (ctx *context) handleInboundInvitation(invitation *Invitation, thid string) error {
	// create a request from invitation
	destination := &dispatcher.Destination{
		RecipientKeys:   invitation.RecipientKeys,
		ServiceEndpoint: invitation.ServiceEndpoint,
		RoutingKeys:     invitation.RoutingKeys,
	}
	newDidDoc, err := ctx.didCreator.CreateDID(wallet.WithServiceType(DIDExchangeServiceType))
	if err != nil {
		return err
	}
	// choose the first public key
	sendVerKey := string(newDidDoc.PublicKey[0].Value)
	temp = sendVerKey
	// prepare the request :
	// TODO Service.Handle() is using the ID from the Invitation as the threadID when instead it should be
	//  using this request's ID. issue-280
	request := &Request{
		Type:  ConnectionRequest,
		ID:    thid,
		Label: "",
		Connection: &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		},
	}
	// send the exchange request
	return ctx.outboundDispatcher.Send(request, sendVerKey, destination)
}
func (ctx *context) handleInboundRequest(request *Request) error {
	// create a response from Request
	newDidDoc, err := ctx.didCreator.CreateDID(wallet.WithServiceType(DIDExchangeServiceType))
	if err != nil {
		return err
	}
	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}
	// prepare connection signature
	encodedConnectionSignature, err := prepareConnectionSignature(connection)
	if err != nil {
		return err
	}
	// prepare the response
	response := &Response{
		Type: ConnectionResponse,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		ConnectionSignature: encodedConnectionSignature,
	}

	destination := prepareDestination(request.Connection.DIDDoc)

	sendVerKey := string(newDidDoc.PublicKey[0].Value)
	// send exchange response
	return ctx.outboundDispatcher.Send(response, sendVerKey, destination)
}
func (ctx *context) sendOutboundRequest(msg dispatcher.DIDCommMsg) error {
	if msg.OutboundDestination == nil {
		return fmt.Errorf("outboundDestination cannot be empty for outbound Request")
	}
	destination := &dispatcher.Destination{
		RecipientKeys:   msg.OutboundDestination.RecipientKeys,
		ServiceEndpoint: msg.OutboundDestination.ServiceEndpoint,
		RoutingKeys:     msg.OutboundDestination.RoutingKeys,
	}
	request := &Request{}
	err := json.Unmarshal(msg.Payload, request)
	if err != nil {
		return err
	}
	// choose the first public key
	sendVerKey := string(request.Connection.DIDDoc.PublicKey[0].Value)
	// send the exchange request
	return ctx.outboundDispatcher.Send(request, sendVerKey, destination)
}

func (ctx *context) sendOutboundResponse(msg dispatcher.DIDCommMsg) error {
	if msg.OutboundDestination == nil {
		return fmt.Errorf("outboundDestination cannot be empty for outbound Request")
	}
	destination := &dispatcher.Destination{
		RecipientKeys:   msg.OutboundDestination.RecipientKeys,
		ServiceEndpoint: msg.OutboundDestination.ServiceEndpoint,
		RoutingKeys:     msg.OutboundDestination.RoutingKeys,
	}
	response := &Response{}
	err := json.Unmarshal(msg.Payload, response)
	if err != nil {
		return fmt.Errorf("unmarhalling outbound response: %s", err)
	}

	var connBytes []byte
	sigData, err := base64.URLEncoding.DecodeString(response.ConnectionSignature.SignedData)
	if err != nil {
		return fmt.Errorf("decoding string failed : %s", err)
	}
	if len(sigData) != 0 {
		// trimming the timestamp and only taking out connection attribute Bytes
		connBytes = sigData[bytes.IndexRune(sigData, '{'):]
	}

	connection := &Connection{}
	err = json.Unmarshal(connBytes, connection)
	if err != nil {
		return err
	}
	// choose the first public key
	sendVerKey := string(connection.DIDDoc.PublicKey[0].Value)

	return ctx.outboundDispatcher.Send(response, sendVerKey, destination)
}

// TODO: Need to figure out how to find the destination for outbound request
//  https://github.com/hyperledger/aries-framework-go/issues/282
func prepareDestination(didDoc *did.Doc) *dispatcher.Destination {
	var srvEndPoint string
	for _, v := range didDoc.Service {
		srvEndPoint = v.ServiceEndpoint
	}

	pubKey := didDoc.PublicKey

	recipientKeys := make([]string, len(pubKey))
	for i, v := range pubKey {
		recipientKeys[i] = string(v.Value)
	}
	return &dispatcher.Destination{
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: srvEndPoint,
	}
}

// Encode the connection and convert to Connection Signature as per the spec.
func prepareConnectionSignature(connection *Connection) (*ConnectionSignature, error) {
	connAttribute, err := json.Marshal(connection)
	if err != nil {
		return nil, err
	}
	now := getEpochTime()
	timestamp := strconv.FormatInt(now, 10)
	connString := string(connAttribute)
	concatenateSignData := []byte(timestamp + connString)
	pubKey := connection.DIDDoc.PublicKey[0].Value

	// Todo signature : wallets needs to return signer interface that will have Sign function
	//  where sigData is passed issue-319
	return &ConnectionSignature{
		Type:       "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
		SignedData: base64.URLEncoding.EncodeToString(concatenateSignData),
		SignVerKey: string(pubKey),
	}, nil
}
func (ctx *context) sendOutboundAck(msg dispatcher.DIDCommMsg) error {
	ack := &model.Ack{}
	if msg.OutboundDestination == nil {
		return fmt.Errorf("outboundDestination cannot be empty for outbound Response")
	}
	destination := &dispatcher.Destination{
		RecipientKeys:   msg.OutboundDestination.RecipientKeys,
		ServiceEndpoint: msg.OutboundDestination.ServiceEndpoint,
		RoutingKeys:     msg.OutboundDestination.RoutingKeys,
	}

	err := json.Unmarshal(msg.Payload, ack)
	if err != nil {
		return err
	}
	// TODO : Issue-353
	sendVerKey := temp
	return ctx.outboundDispatcher.Send(ack, sendVerKey, destination)
}
func (ctx *context) handleInboundResponse(response *Response) error {
	ack := &model.Ack{
		Type:   ConnectionAck,
		ID:     uuid.New().String(),
		Status: ackStatusOK,
		Thread: &decorator.Thread{
			ID: response.Thread.ID,
		},
	}

	var connBytes []byte
	sigData, err := base64.URLEncoding.DecodeString(response.ConnectionSignature.SignedData)
	if err != nil {
		return fmt.Errorf("decoding string failed : %s", err)
	}
	if len(sigData) != 0 {
		// trimming the timestamp and only taking out connection attribute Bytes
		connBytes = sigData[bytes.IndexRune(sigData, '{'):]
	}
	conn := &Connection{}
	err = json.Unmarshal(connBytes, conn)
	if err != nil {
		return fmt.Errorf("unmarshalling failed : %s", err)
	}
	dest := prepareDestination(conn.DIDDoc)
	// TODO : Issue-353
	sendVerKey := temp
	return ctx.outboundDispatcher.Send(ack, sendVerKey, dest)
}

func getEpochTime() int64 {
	return time.Now().Unix()
}
