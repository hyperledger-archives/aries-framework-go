/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
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
)

// The did-exchange protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	Execute(msg dispatcher.DIDCommMsg, ctx context) (followup state, err error)
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

func (s *noOp) Execute(_ dispatcher.DIDCommMsg, ctx context) (state, error) {
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

func (s *null) Execute(msg dispatcher.DIDCommMsg, ctx context) (state, error) {
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

func (s *invited) Execute(msg dispatcher.DIDCommMsg, ctx context) (state, error) {
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

func (s *requested) Execute(msg dispatcher.DIDCommMsg, ctx context) (state, error) {
	switch msg.Type {
	case ConnectionInvite:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound invitations are not allowed for state %s", s.Name())
		}
		invitation := &Invitation{}
		err := json.Unmarshal(msg.Payload, invitation)
		if err != nil {
			return nil, err
		}
		err = ctx.handleInboundInvitation(invitation)
		if err != nil {
			return nil, err
		}
		return &noOp{}, nil
	case ConnectionRequest:
		if msg.Outbound {
			// send outbound Request
			request, destination, err := ctx.createOutboundRequest(msg)
			if err != nil {
				return nil, err
			}
			err = ctx.sendExchangeRequest(request, destination)
			if err != nil {
				return nil, err
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

func (s *responded) Execute(msg dispatcher.DIDCommMsg, ctx context) (state, error) {
	switch msg.Type {
	case ConnectionRequest:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound requests are not allowed for state %s", s.Name())
		}
		request := &Request{}
		err := json.Unmarshal(msg.Payload, request)
		if err != nil {
			return nil, err
		}
		err = ctx.handleInboundRequest(request)
		if err != nil {
			return nil, err
		}
		return &noOp{}, nil
	case ConnectionResponse:
		if msg.Outbound {
			response, destination, err := ctx.createOutboundResponse(msg)
			if err != nil {
				return nil, err
			}
			err = ctx.sendOutbound(response, destination)
			if err != nil {
				return nil, err
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

func (s *completed) Execute(msg dispatcher.DIDCommMsg, ctx context) (state, error) {
	switch msg.Type {
	case ConnectionResponse:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound responses are not allowed for state %s", s.Name())
		}
		// send ACK
		return &noOp{}, nil
	case ConnectionAck:
		// if msg.Outbound send ACK
		// otherwise save did-exchange connection
		return &noOp{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
}

func (ctx *context) newRequestFromInvitation(invitation *Invitation) (*Request, *dispatcher.Destination, error) {
	dest := &dispatcher.Destination{
		RecipientKeys:   invitation.RecipientKeys,
		ServiceEndpoint: invitation.ServiceEndpoint,
		RoutingKeys:     invitation.RoutingKeys,
	}

	newDidDoc, err := ctx.didWallet.CreateDID(didMethod, wallet.WithServiceType(DIDExchangeServiceType))
	if err != nil {
		return nil, nil, err
	}
	//prepare the request :TODO Service.Handle() is using the ID from the Invitation as the threadID when instead it should be using this request's ID. issue-280
	request := &Request{
		Type:  ConnectionRequest,
		ID:    uuid.New().String(),
		Label: "Bob", //TODO: How to figure out the label of the request - https://github.com/hyperledger/aries-framework-go/issues/281
		Connection: &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		},
	}
	return request, dest, nil
}

func (ctx *context) handleInboundInvitation(invitation *Invitation) error {
	request, destination, err := ctx.newRequestFromInvitation(invitation)
	if err != nil {
		return err
	}
	return ctx.sendExchangeRequest(request, destination)
}

func (ctx *context) handleInboundRequest(request *Request) error {
	response, destination, err := ctx.newResponseFromRequest(request)
	if err != nil {
		return err
	}
	return ctx.sendExchangeResponse(response, destination)
}

func (ctx *context) sendExchangeRequest(request *Request, destination *dispatcher.Destination) error {
	//TODO:Send ver key issue-299
	sendVerKey := ""
	//send the exchange request
	return ctx.outboundDispatcher.Send(request, sendVerKey, destination)
}

func (ctx *context) createOutboundRequest(msg dispatcher.DIDCommMsg) (*Request, *dispatcher.Destination, error) {
	request := &Request{}
	if msg.OutboundDestination == nil {
		return nil, nil, fmt.Errorf("OutboundDestination cannot be empty for outbound Request")
	}
	destination := &dispatcher.Destination{
		RecipientKeys:   msg.OutboundDestination.RecipientKeys,
		ServiceEndpoint: msg.OutboundDestination.ServiceEndpoint,
		RoutingKeys:     msg.OutboundDestination.RoutingKeys,
	}

	err := json.Unmarshal(msg.Payload, request)
	if err != nil {
		return nil, nil, err
	}
	return request, destination, nil
}

func (ctx *context) createOutboundResponse(msg dispatcher.DIDCommMsg) (*Response, *dispatcher.Destination, error) {
	response := &Response{}
	if msg.OutboundDestination == nil {
		return nil, nil, fmt.Errorf("OutboundDestination cannot be empty for outbound Response")

	}
	destination := &dispatcher.Destination{
		RecipientKeys:   msg.OutboundDestination.RecipientKeys,
		ServiceEndpoint: msg.OutboundDestination.ServiceEndpoint,
		RoutingKeys:     msg.OutboundDestination.RoutingKeys,
	}

	err := json.Unmarshal(msg.Payload, response)
	if err != nil {
		return nil, nil, err
	}
	return response, destination, nil
}

func (ctx *context) sendOutbound(msg interface{}, destination *dispatcher.Destination) error {
	//TODO:Send ver key issue-299
	sendVerKey := ""
	return ctx.outboundDispatcher.Send(msg, sendVerKey, destination)
}

func (ctx *context) newResponseFromRequest(request *Request) (*Response, *dispatcher.Destination, error) {
	newDidDoc, err := ctx.didWallet.CreateDID(didMethod, wallet.WithServiceType(DIDExchangeServiceType))
	if err != nil {
		return nil, nil, err
	}
	connection := &Connection{
		DID:    newDidDoc.ID,
		DIDDoc: newDidDoc,
	}
	//prepare connection signature
	encodedConnectionSignature, err := prepareConnectionSignature(connection)
	if err != nil {
		return nil, nil, err
	}
	//prepare the response
	response := &Response{
		Type: ConnectionResponse,
		ID:   uuid.New().String(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		ConnectionSignature: encodedConnectionSignature,
	}
	requestDoc := request.Connection.DIDDoc
	destination := prepareDestination(requestDoc)

	return response, destination, nil
}

func (ctx *context) sendExchangeResponse(response *Response, destination *dispatcher.Destination) error {
	//TODO:Send ver key issue-299
	sendVerKey := ""
	//send exchange response
	return ctx.outboundDispatcher.Send(response, sendVerKey, destination)
}

// TODO: Need to figure out how to find the destination for outbound request - https://github.com/hyperledger/aries-framework-go/issues/282
func prepareDestination(didDoc *did.Doc) *dispatcher.Destination {
	var srvEndPoint string
	for _, v := range didDoc.Service {
		srvEndPoint = v.ServiceEndpoint
	}

	pubKey := didDoc.PublicKey

	recipientKeys := make([]string, len(pubKey))
	for i, v := range pubKey {
		recipientKeys[i] = fmt.Sprint(v)
	}
	return &dispatcher.Destination{
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: srvEndPoint,
	}
}

//Encode the connection and convert to Connection Signature as per the spec.
func prepareConnectionSignature(connection *Connection) (*ConnectionSignature, error) {
	conBytes, err := json.Marshal(connection)
	if err != nil {
		return nil, err
	}
	sigData := base64.StdEncoding.EncodeToString(conBytes)
	//TODO - compute the actual signature and add it issue-319
	return &ConnectionSignature{
		Type:       "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
		SignedData: sigData}, nil
}
