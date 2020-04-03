/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
)

type (
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation presentproof.RequestPresentation
	// Presentation is a response to a RequestPresentation message and contains signed presentations.
	Presentation presentproof.Presentation
	// ProposePresentation is an optional message sent by the Prover to the verifier to initiate a proof
	// presentation process, or in response to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation presentproof.ProposePresentation
)

var (
	errEmptyRequestPresentation = errors.New("request presentation message is empty")
	errEmptyProposePresentation = errors.New("propose presentation message is empty")
)

// Provider contains dependencies for the protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the presentproof service.
type ProtocolService interface {
	service.DIDComm
	Actions() ([]presentproof.Action, error)
	ActionContinue(piID string, opt presentproof.Opt) error
	ActionStop(piID string, err error) error
}

// Client enable access to presentproof API
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof
type Client struct {
	service.Event
	service ProtocolService
}

// New returns new instance of the presentproof client
func New(ctx Provider) (*Client, error) {
	raw, err := ctx.Service(presentproof.Name)
	if err != nil {
		return nil, err
	}

	svc, ok := raw.(ProtocolService)
	if !ok {
		return nil, errors.New("cast service to presentproof service failed")
	}

	return &Client{
		Event:   svc,
		service: svc,
	}, nil
}

// Actions returns pending actions that have yet to be executed or cancelled.
func (c *Client) Actions() ([]presentproof.Action, error) {
	return c.service.Actions()
}

// SendRequestPresentation is used by the Verifier to send a request presentation.
func (c *Client) SendRequestPresentation(msg *RequestPresentation, myDID, theirDID string) error {
	if msg == nil {
		return errEmptyRequestPresentation
	}

	msg.Type = presentproof.RequestPresentationMsgType

	_, err := c.service.HandleInbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)

	return err
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (c *Client) AcceptRequestPresentation(piID string, msg *Presentation) error {
	return c.service.ActionContinue(piID, WithPresentation(msg))
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (c *Client) NegotiateRequestPresentation(piID string, msg *ProposePresentation) error {
	return c.service.ActionContinue(piID, WithProposePresentation(msg))
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (c *Client) DeclineRequestPresentation(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// SendProposePresentation is used by the Prover to send a propose presentation.
func (c *Client) SendProposePresentation(msg *ProposePresentation, myDID, theirDID string) error {
	if msg == nil {
		return errEmptyProposePresentation
	}

	msg.Type = presentproof.ProposePresentationMsgType

	_, err := c.service.HandleInbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)

	return err
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (c *Client) AcceptProposePresentation(piID string, msg *RequestPresentation) error {
	return c.service.ActionContinue(piID, WithRequestPresentation(msg))
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (c *Client) DeclineProposePresentation(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (c *Client) AcceptPresentation(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (c *Client) DeclinePresentation(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// WithPresentation allows providing Presentation message
// Use this option to respond to RequestPresentation
func WithPresentation(msg *Presentation) presentproof.Opt {
	origin := presentproof.Presentation(*msg)
	return presentproof.WithPresentation(&origin)
}

// WithProposePresentation allows providing ProposePresentation message
// Use this option to respond to RequestPresentation
func WithProposePresentation(msg *ProposePresentation) presentproof.Opt {
	origin := presentproof.ProposePresentation(*msg)
	return presentproof.WithProposePresentation(&origin)
}

// WithRequestPresentation allows providing RequestPresentation message
// Use this option to respond to ProposePresentation
func WithRequestPresentation(msg *RequestPresentation) presentproof.Opt {
	origin := presentproof.RequestPresentation(*msg)
	return presentproof.WithRequestPresentation(&origin)
}
