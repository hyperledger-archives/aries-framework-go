/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
	// RequestPresentationV3 describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentationV3 presentproof.RequestPresentationV3
	// PresentationV3 is a response to a RequestPresentationV3 message and contains signed presentations.
	PresentationV3 presentproof.PresentationV3
	// ProposePresentationV3 is an optional message sent by the Prover to the verifier to initiate a proof
	// presentation process, or in response to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentationV3 presentproof.ProposePresentationV3
	// Action contains helpful information about action.
	Action presentproof.Action
)

const (
	// web redirect decorator.
	webRedirectDecorator  = "~web-redirect"
	webRedirectStatusOK   = "OK"
	webRedirectStatusFAIL = "FAIL"
)

var (
	errEmptyRequestPresentation = errors.New("request presentation message is empty")
	errEmptyProposePresentation = errors.New("propose presentation message is empty")
)

// Provider contains dependencies for the protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the presentproof service.
type ProtocolService interface {
	service.DIDComm
	Actions() ([]presentproof.Action, error)
	ActionContinue(piID string, opt ...presentproof.Opt) error
	ActionStop(piID string, err error, opt ...presentproof.Opt) error
}

// Client enable access to presentproof API
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof
type Client struct {
	service.Event
	service ProtocolService
}

// New returns new instance of the presentproof client.
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

// SendRequestPresentation is used by the Verifier to send a request presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendRequestPresentation(msg *RequestPresentation, myDID, theirDID string) (string, error) {
	if msg == nil {
		return "", errEmptyRequestPresentation
	}

	msg.Type = presentproof.RequestPresentationMsgTypeV2

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
}

// SendRequestPresentationV3 is used by the Verifier to send a request presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendRequestPresentationV3(msg *RequestPresentationV3, myDID, theirDID string) (string, error) {
	if msg == nil {
		return "", errEmptyRequestPresentation
	}

	msg.Type = presentproof.RequestPresentationMsgTypeV3

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
}

type addProof func(presentation *verifiable.Presentation) error

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (c *Client) AcceptRequestPresentation(piID string, msg *Presentation, sign addProof) error {
	return c.service.ActionContinue(piID, WithMultiOptions(WithPresentation(msg), WithAddProofFn(sign)))
}

// AcceptRequestPresentationV3 is used by the Prover is to accept a presentation request.
func (c *Client) AcceptRequestPresentationV3(piID string, msg *PresentationV3, sign addProof) error {
	return c.service.ActionContinue(piID, WithMultiOptions(WithPresentationV3(msg), WithAddProofFn(sign)))
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (c *Client) NegotiateRequestPresentation(piID string, msg *ProposePresentation) error {
	return c.service.ActionContinue(piID, WithProposePresentation(msg))
}

// NegotiateRequestPresentationV3 is used by the Prover to counter a presentation request they received with a proposal.
func (c *Client) NegotiateRequestPresentationV3(piID string, msg *ProposePresentationV3) error {
	return c.service.ActionContinue(piID, WithProposePresentationV3(msg))
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (c *Client) DeclineRequestPresentation(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// SendProposePresentation is used by the Prover to send a propose presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendProposePresentation(msg *ProposePresentation, myDID, theirDID string) (string, error) {
	if msg == nil {
		return "", errEmptyProposePresentation
	}

	msg.Type = presentproof.ProposePresentationMsgTypeV2

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
}

// SendProposePresentationV3 is used by the Prover to send a propose presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendProposePresentationV3(msg *ProposePresentationV3, myDID, theirDID string) (string, error) {
	if msg == nil {
		return "", errEmptyProposePresentation
	}

	msg.Type = presentproof.ProposePresentationMsgTypeV3

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (c *Client) AcceptProposePresentation(piID string, msg *RequestPresentation) error {
	return c.service.ActionContinue(piID, WithRequestPresentation(msg))
}

// AcceptProposePresentationV3 is used when the Verifier is willing to accept the propose presentation.
func (c *Client) AcceptProposePresentationV3(piID string, msg *RequestPresentationV3) error {
	return c.service.ActionContinue(piID, WithRequestPresentationV3(msg))
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (c *Client) DeclineProposePresentation(piID string, options ...DeclinePresentationOptions) error {
	opts := &declinePresentationOpts{}

	for _, option := range options {
		option(opts)
	}

	return c.service.ActionStop(piID, opts.reason, prepareRedirectProperties(opts.redirect, webRedirectStatusFAIL))
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (c *Client) AcceptPresentation(piID string, options ...AcceptPresentationOptions) error {
	opts := &acceptPresentationOpts{}

	for _, option := range options {
		option(opts)
	}

	return c.service.ActionContinue(piID, presentproof.WithFriendlyNames(opts.names...),
		prepareRedirectProperties(opts.redirect, webRedirectStatusOK))
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (c *Client) DeclinePresentation(piID string, options ...DeclinePresentationOptions) error {
	opts := &declinePresentationOpts{}

	for _, option := range options {
		option(opts)
	}

	return c.service.ActionStop(piID, opts.reason, prepareRedirectProperties(opts.redirect, webRedirectStatusFAIL))
}

// AcceptProblemReport accepts problem report action.
func (c *Client) AcceptProblemReport(piID string) error {
	return c.service.ActionContinue(piID)
}

// WithPresentation allows providing Presentation message
// Use this option to respond to RequestPresentation.
func WithPresentation(msg *Presentation) presentproof.Opt {
	origin := presentproof.Presentation(*msg)

	return presentproof.WithPresentation(&origin)
}

// WithPresentationV3 allows providing PresentationV3 message
// Use this option to respond to RequestPresentationV3.
func WithPresentationV3(msg *PresentationV3) presentproof.Opt {
	origin := presentproof.PresentationV3(*msg)

	return presentproof.WithPresentationV3(&origin)
}

// WithMultiOptions allows combining several options into one.
func WithMultiOptions(opts ...presentproof.Opt) presentproof.Opt {
	return presentproof.WithMultiOptions(opts...)
}

// WithAddProofFn allows providing function that will sign the Presentation.
// Use this option to respond to RequestPresentation.
func WithAddProofFn(sign addProof) presentproof.Opt {
	return presentproof.WithAddProofFn(sign)
}

// WithProposePresentation allows providing ProposePresentation message
// Use this option to respond to RequestPresentation.
func WithProposePresentation(msg *ProposePresentation) presentproof.Opt {
	origin := presentproof.ProposePresentation(*msg)

	return presentproof.WithProposePresentation(&origin)
}

// WithProposePresentationV3 allows providing ProposePresentationV3 message
// Use this option to respond to RequestPresentation.
func WithProposePresentationV3(msg *ProposePresentationV3) presentproof.Opt {
	origin := presentproof.ProposePresentationV3(*msg)

	return presentproof.WithProposePresentationV3(&origin)
}

// WithRequestPresentation allows providing RequestPresentation message
// Use this option to respond to ProposePresentation.
func WithRequestPresentation(msg *RequestPresentation) presentproof.Opt {
	origin := presentproof.RequestPresentation(*msg)

	return presentproof.WithRequestPresentation(&origin)
}

// WithRequestPresentationV3 allows providing RequestPresentation message
// Use this option to respond to ProposePresentation.
func WithRequestPresentationV3(msg *RequestPresentationV3) presentproof.Opt {
	origin := presentproof.RequestPresentationV3(*msg)

	return presentproof.WithRequestPresentationV3(&origin)
}

// create web redirect properties to add ~web-redirect decorator.
func prepareRedirectProperties(redirect, status string) presentproof.Opt {
	properties := map[string]interface{}{}

	if redirect != "" {
		properties[webRedirectDecorator] = &decorator.WebRedirect{
			Status: status,
			URL:    redirect,
		}
	}

	return presentproof.WithProperties(properties)
}

// declinePresentationOpts options for declining propose presentation and presentation.
type declinePresentationOpts struct {
	reason   error
	redirect string
}

// DeclinePresentationOptions is custom option for declining propose presentation and presentation messages from prover.
type DeclinePresentationOptions func(opts *declinePresentationOpts)

// DeclineReason option to provide optional reason for declining given message.
func DeclineReason(reason string) DeclinePresentationOptions {
	return func(opts *declinePresentationOpts) {
		if reason != "" {
			opts.reason = errors.New(reason)
		}
	}
}

// DeclineRedirect option to provide optional redirect URL requesting prover to redirect.
func DeclineRedirect(url string) DeclinePresentationOptions {
	return func(opts *declinePresentationOpts) {
		opts.redirect = url
	}
}

// acceptPresentationOpts options for accepting presentation message.
type acceptPresentationOpts struct {
	names    []string
	redirect string
}

// AcceptPresentationOptions is custom option for accepting presentation message from prover.
type AcceptPresentationOptions func(opts *acceptPresentationOpts)

// AcceptByFriendlyNames option to provide optional friendly names for accepting presentation message.
func AcceptByFriendlyNames(names ...string) AcceptPresentationOptions {
	return func(opts *acceptPresentationOpts) {
		opts.names = names
	}
}

// AcceptByRequestingRedirect option to provide optional redirect URL requesting prover to redirect.
func AcceptByRequestingRedirect(url string) AcceptPresentationOptions {
	return func(opts *acceptPresentationOpts) {
		opts.redirect = url
	}
}
