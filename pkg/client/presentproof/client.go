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
	// Action contains helpful information about action.
	Action presentproof.Action
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

	msg.Type = presentproof.RequestPresentationMsgType

	return c.service.HandleInbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
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
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendProposePresentation(msg *ProposePresentation, myDID, theirDID string) (string, error) {
	if msg == nil {
		return "", errEmptyProposePresentation
	}

	msg.Type = presentproof.ProposePresentationMsgType

	return c.service.HandleInbound(service.NewDIDCommMsgMap(msg), myDID, theirDID)
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
func (c *Client) AcceptPresentation(piID string, names ...string) error {
	return c.service.ActionContinue(piID, WithFriendlyNames(names...))
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (c *Client) DeclinePresentation(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptProblemReport accepts problem report action.
func (c *Client) AcceptProblemReport(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// InputDescriptor dummy input descriptor structure.
// This struct includes the following payload proposal~attach.data.json.input_descriptors[0]
// To find out more please visit
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0510-dif-pres-exch-attach#propose-presentation-attachment-format
// e.g
// {
//   "id":"citizenship_input",
//   "group":[ ... ],
//   "schema":{ ... },
//   "constraints":{
//      "fields":[...]
//   }
// }
type InputDescriptor struct{}

// SubmissionRequirement dummy submission requirement structure
// This struct includes the following payload
// request_presentations~attach.data.json.presentation_definitions.submission_requirement.
// To find out more please visit https://github.com/hyperledger/aries-rfcs/tree/master/features/0510-dif-pres-exch-attach#propose-presentation-attachment-format
// e.g
// {
//   "name":"Credential issuance requirements",
//   "purpose":"...",
//   "rule":"all",
//   "from":[ ... ]
// }
type SubmissionRequirement struct{}

// RequestPresentationExt represents request presentation extension
type RequestPresentationExt struct {
	Challenge               string `json:"challenge"`
	Domain                  string `json:"domain"`
	PresentationDefinitions struct {
		InputDescriptors      []InputDescriptor     `json:"input_descriptors"`
		SubmissionRequirement SubmissionRequirement `json:"submission_requirement"`
	} `json:"presentation_definitions"`
}

// PresentationExt represents presentation extension
// This struct includes the following payload presentations~attach.data.json. To find out more please visit
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0510-dif-pres-exch-attach#presentation-attachment-format
// e.g
// {
//   "@context":[ ... ],
//   "type":[ ... ],
//   "presentation_submission":{ ... },
//   "verifiableCredential":[ ... ],
//   "proof":{ ... }
// }
type PresentationExt struct{}

// SendProposePresentationDesc is used by the Prover to send a propose presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendProposePresentationDesc(myDID, theirDID string, _ *[]InputDescriptor) (string, error) {
	return "", errors.New("not implemented")
}

// NegotiateRequestPresentationDesc is used by the Prover to counter a presentation
// request they received with a proposal.
func (c *Client) NegotiateRequestPresentationDesc(piID string, _ *[]InputDescriptor) error {
	return errors.New("not implemented")
}

// SendRequestPresentationExt is used by the Verifier to send a request presentation.
// It returns the threadID of the new instance of the protocol.
func (c *Client) SendRequestPresentationExt(myDID, theirDID string, _ *RequestPresentationExt) (string, error) {
	return "", errors.New("not implemented")
}

// AcceptProposePresentationExt is used when the Verifier is willing to accept the propose presentation.
func (c *Client) AcceptProposePresentationExt(piID string, _ *RequestPresentationExt) error {
	return errors.New("not implemented")
}

// AcceptRequestPresentationExt is used by the Prover is to accept a presentation request.
func (c *Client) AcceptRequestPresentationExt(piID string, msg *PresentationExt) error {
	return errors.New("not implemented")
}

// WithPresentation allows providing Presentation message
// Use this option to respond to RequestPresentation.
func WithPresentation(msg *Presentation) presentproof.Opt {
	origin := presentproof.Presentation(*msg)
	return presentproof.WithPresentation(&origin)
}

// WithProposePresentation allows providing ProposePresentation message
// Use this option to respond to RequestPresentation.
func WithProposePresentation(msg *ProposePresentation) presentproof.Opt {
	origin := presentproof.ProposePresentation(*msg)
	return presentproof.WithProposePresentation(&origin)
}

// WithRequestPresentation allows providing RequestPresentation message
// Use this option to respond to ProposePresentation.
func WithRequestPresentation(msg *RequestPresentation) presentproof.Opt {
	origin := presentproof.RequestPresentation(*msg)
	return presentproof.WithRequestPresentation(&origin)
}

// WithFriendlyNames allows providing names for the presentations.
func WithFriendlyNames(names ...string) presentproof.Opt {
	return presentproof.WithFriendlyNames(names...)
}
