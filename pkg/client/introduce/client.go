/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
)

type (
	// To introducee descriptor keeps information about the introduction.
	To introduce.To
	// PleaseIntroduceTo includes all field from To structure
	// also it has Discovered the field which should be provided by help-me-discover protocol.
	PleaseIntroduceTo introduce.PleaseIntroduceTo
	// Recipient keeps information needed for the service
	// 'To' field is needed for the proposal message
	// 'MyDID' and 'TheirDID' fields are needed for sending messages e.g report-problem, proposal, ack etc.
	Recipient introduce.Recipient
	// Action contains helpful information about action.
	Action introduce.Action
)

// Provider contains dependencies for the introduce protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the introduce service.
type ProtocolService interface {
	service.DIDComm
	Actions() ([]introduce.Action, error)
	ActionContinue(piID string, opt introduce.Opt) error
	ActionStop(piID string, err error) error
}

// Client enable access to introduce API.
type Client struct {
	service.Event
	service ProtocolService
}

// New return new instance of introduce client.
func New(ctx Provider) (*Client, error) {
	svc, err := ctx.Service(introduce.Introduce)
	if err != nil {
		return nil, err
	}

	introduceSvc, ok := svc.(ProtocolService)
	if !ok {
		return nil, errors.New("cast service to Introduce Service failed")
	}

	return &Client{
		Event:   introduceSvc,
		service: introduceSvc,
	}, nil
}

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
func (c *Client) SendProposal(recipient1, recipient2 *Recipient) (string, error) {
	_recipient1 := introduce.Recipient(*recipient1)
	_recipient2 := introduce.Recipient(*recipient2)

	proposal1 := introduce.CreateProposal(&_recipient1)
	proposal2 := introduce.CreateProposal(&_recipient2)

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := c.service.HandleOutbound(proposal1, recipient1.MyDID, recipient1.TheirDID)
	if err != nil {
		return "", fmt.Errorf("handle outbound: %w", err)
	}

	return c.service.HandleOutbound(proposal2, recipient2.MyDID, recipient2.TheirDID)
}

// SendProposalWithOOBInvitation sends a proposal to the introducee (the client has published an out-of-band request).
func (c *Client) SendProposalWithOOBInvitation(inv *outofband.Invitation, recipient *Recipient) (string, error) {
	_recipient := introduce.Recipient(*recipient)
	_req := outofbandsvc.Invitation(*inv)

	proposal := introduce.CreateProposal(&_recipient)
	introduce.WrapWithMetadataPublicOOBInvitation(proposal, &_req)

	return c.service.HandleOutbound(proposal, recipient.MyDID, recipient.TheirDID)
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share their own out-of-band message.
func (c *Client) SendRequest(to *PleaseIntroduceTo, myDID, theirDID string) (string, error) {
	_to := introduce.PleaseIntroduceTo(*to)

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type:              introduce.RequestMsgType,
		PleaseIntroduceTo: &_to,
	}), myDID, theirDID)
}

// AcceptProposalWithOOBInvitation is used when introducee wants to provide an out-of-band request.
// Introducee can provide this request only after receiving ProposalMsgType.
func (c *Client) AcceptProposalWithOOBInvitation(piID string, inv *outofband.Invitation) error {
	return c.service.ActionContinue(piID, WithOOBInvitation(inv))
}

// AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest.
func (c *Client) AcceptProposal(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// AcceptRequestWithPublicOOBInvitation is used when introducer wants to provide a published out-of-band request.
// Introducer can provide invitation only after receiving RequestMsgType.
func (c *Client) AcceptRequestWithPublicOOBInvitation(piID string, inv *outofband.Invitation, to *To) error {
	return c.service.ActionContinue(piID, WithPublicOOBInvitation(inv, to))
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
// Introducer can provide recipients only after receiving RequestMsgType.
func (c *Client) AcceptRequestWithRecipients(piID string, to *To, recipient *Recipient) error {
	return c.service.ActionContinue(piID, WithRecipients(to, recipient))
}

// DeclineProposal is used to reject the proposal.
// NOTE: For async usage.
func (c *Client) DeclineProposal(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// DeclineRequest is used to reject the request.
// NOTE: For async usage.
func (c *Client) DeclineRequest(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptProblemReport accepts problem report action.
func (c *Client) AcceptProblemReport(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// Actions returns unfinished actions for the async usage.
func (c *Client) Actions() ([]Action, error) {
	actions, err := c.service.Actions()
	if err != nil {
		return nil, err
	}

	result := make([]Action, len(actions))
	for i, action := range actions {
		result[i] = Action(action)
	}

	return result, nil
}

// WithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
// NOTE: Introducer can provide recipients only after receiving RequestMsgType.
// USAGE: event.Continue(WithRecipients(to, recipient)).
func WithRecipients(to *To, recipient *Recipient) introduce.Opt {
	_to := introduce.To(*to)
	_recipient := introduce.Recipient(*recipient)

	return introduce.WithRecipients(&_to, &_recipient)
}

// WithPublicOOBInvitation is used when introducer wants to provide a published out-of-band request.
// NOTE: Introducer can provide this request only after receiving RequestMsgType
// USAGE: event.Continue(WithPublicOOBInvitation(req, to)).
func WithPublicOOBInvitation(req *outofband.Invitation, to *To) introduce.Opt {
	_to := introduce.To(*to)
	_req := outofbandsvc.Invitation(*req)

	return introduce.WithPublicOOBInvitation(&_req, &_to)
}

// WithOOBInvitation is used when introducee wants to provide an out-of-band request with an optional
// series of attachments.
// NOTE: Introducee can provide the request only after receiving ProposalMsgType
// USAGE: event.Continue(WithOOBInvitation(inv)).
func WithOOBInvitation(req *outofband.Invitation, a ...*decorator.Attachment) introduce.Opt {
	_req := outofbandsvc.Invitation(*req)

	return introduce.WithOOBInvitation(&_req, a...)
}
