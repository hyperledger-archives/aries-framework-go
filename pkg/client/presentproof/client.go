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
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

type (
	// ProposePresentation is an optional message sent by the Prover to the verifier to initiate a proof
	// presentation process, or in response to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentation = presentproof.ProposePresentationParams
	// RequestPresentation describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentation = presentproof.RequestPresentationParams
	// Presentation is a response to a RequestPresentation message and contains signed presentations.
	Presentation = presentproof.PresentationParams
	// ProposePresentationV2 is an optional message sent by the Prover to the verifier to initiate a proof
	// presentation process, or in response to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentationV2 presentproof.ProposePresentationV2
	// RequestPresentationV2 describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentationV2 presentproof.RequestPresentationV2
	// PresentationV2 is a response to a RequestPresentationV2 message and contains signed presentations.
	PresentationV2 presentproof.PresentationV2
	// ProposePresentationV3 is an optional message sent by the Prover to the verifier to initiate a proof
	// presentation process, or in response to a request-presentation message when the Prover wants to
	// propose using a different presentation format.
	ProposePresentationV3 presentproof.ProposePresentationV3
	// RequestPresentationV3 describes values that need to be revealed and predicates that need to be fulfilled.
	RequestPresentationV3 presentproof.RequestPresentationV3
	// PresentationV3 is a response to a RequestPresentationV3 message and contains signed presentations.
	PresentationV3 presentproof.PresentationV3
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
func (c *Client) SendRequestPresentation(
	params *RequestPresentation, connRec *connection.Record) (string, error) {
	if params == nil {
		return "", errEmptyRequestPresentation
	}

	switch connRec.DIDCommVersion {
	default:
		fallthrough // use didcomm v1 + present-proof v2 by default, if the connection record doesn't indicate version.
	case service.V1:
		return c.service.HandleOutbound(service.NewDIDCommMsgMap(&RequestPresentationV2{
			Type:                       presentproof.RequestPresentationMsgTypeV2,
			Comment:                    params.Comment,
			WillConfirm:                params.WillConfirm,
			Formats:                    params.Formats,
			RequestPresentationsAttach: decorator.GenericAttachmentsToV1(params.Attachments),
		}), connRec.MyDID, connRec.TheirDID)
	case service.V2:
		return c.service.HandleOutbound(service.NewDIDCommMsgMap(&RequestPresentationV3{
			Type: presentproof.RequestPresentationMsgTypeV3,
			Body: presentproof.RequestPresentationV3Body{
				GoalCode:    params.GoalCode,
				Comment:     params.Comment,
				WillConfirm: params.WillConfirm,
			},
			Attachments: decorator.GenericAttachmentsToV2(params.Attachments),
		}), connRec.MyDID, connRec.TheirDID)
	}
}

type addProof func(presentation *verifiable.Presentation) error

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (c *Client) AcceptRequestPresentation(piID string, msg *Presentation, sign addProof) error {
	return c.service.ActionContinue(piID, WithMultiOptions(WithPresentation(msg), WithAddProofFn(sign)))
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
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendProposePresentation(
	params *ProposePresentation, connRec *connection.Record) (string, error) {
	if params == nil {
		return "", errEmptyProposePresentation
	}

	switch connRec.DIDCommVersion {
	default:
		fallthrough // use didcomm v1 + present-proof v2 by default, if the connection record doesn't indicate version.
	case service.V1:
		return c.service.HandleOutbound(service.NewDIDCommMsgMap(&ProposePresentationV2{
			Type:            presentproof.ProposePresentationMsgTypeV2,
			Comment:         params.Comment,
			Formats:         params.Formats,
			ProposalsAttach: decorator.GenericAttachmentsToV1(params.Attachments),
		}), connRec.MyDID, connRec.TheirDID)
	case service.V2:
		return c.service.HandleOutbound(service.NewDIDCommMsgMap(&ProposePresentationV3{
			Type: presentproof.ProposePresentationMsgTypeV3,
			Body: presentproof.ProposePresentationV3Body{
				GoalCode: params.GoalCode,
				Comment:  params.Comment,
			},
			Attachments: decorator.GenericAttachmentsToV2(params.Attachments),
		}), connRec.MyDID, connRec.TheirDID)
	}
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (c *Client) AcceptProposePresentation(piID string, msg *RequestPresentation) error {
	return c.service.ActionContinue(piID, WithRequestPresentation(msg))
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

// WithPresentation allows providing Presentation message.
// Use this option to respond to RequestPresentation.
func WithPresentation(msg *Presentation) presentproof.Opt {
	return presentproof.WithPresentation(msg)
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

// WithProposePresentation allows providing ProposePresentation message.
// Use this option to respond to RequestPresentation.
func WithProposePresentation(msg *ProposePresentation) presentproof.Opt {
	return presentproof.WithProposePresentation(msg)
}

// WithRequestPresentation allows providing RequestPresentation message.
// Use this option to respond to ProposePresentation.
func WithRequestPresentation(msg *RequestPresentation) presentproof.Opt {
	return presentproof.WithRequestPresentation(msg)
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
