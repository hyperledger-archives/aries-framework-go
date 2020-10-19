/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
)

var (
	errEmptyOffer    = errors.New("received an empty offer")
	errEmptyProposal = errors.New("received an empty proposal")
	errEmptyRequest  = errors.New("received an empty request")
)

type (
	// OfferCredential is a message sent by the Issuer to the potential Holder,
	// describing the credential they intend to offer and possibly the price they expect to be paid.
	OfferCredential issuecredential.OfferCredential
	// ProposeCredential is an optional message sent by the potential Holder to the Issuer
	// to initiate the protocol or in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredential issuecredential.ProposeCredential
	// RequestCredential is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential. Where circumstances do not require
	// a preceding Offer Credential message (e.g., there is no cost to issuance
	// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
	// this message initiates the protocol.
	RequestCredential issuecredential.RequestCredential
	// IssueCredential contains as attached payload the credentials being issued and is
	// sent in response to a valid Request Credential message.
	IssueCredential issuecredential.IssueCredential
	// Action contains helpful information about action.
	Action issuecredential.Action
)

// Provider contains dependencies for the issuecredential protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the issuecredential service.
type ProtocolService interface {
	service.DIDComm
	Actions() ([]issuecredential.Action, error)
	ActionContinue(piID string, opt issuecredential.Opt) error
	ActionStop(piID string, err error) error
}

// Client enable access to issuecredential API.
type Client struct {
	service.Event
	service ProtocolService
}

// New return new instance of the issuecredential client.
func New(ctx Provider) (*Client, error) {
	raw, err := ctx.Service(issuecredential.Name)
	if err != nil {
		return nil, err
	}

	svc, ok := raw.(ProtocolService)
	if !ok {
		return nil, errors.New("cast service to issuecredential service failed")
	}

	return &Client{
		Event:   svc,
		service: svc,
	}, nil
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

// SendOffer is used by the Issuer to send an offer.
func (c *Client) SendOffer(offer *OfferCredential, myDID, theirDID string) (string, error) {
	if offer == nil {
		return "", errEmptyOffer
	}

	offer.Type = issuecredential.OfferCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(offer), myDID, theirDID)
}

// SendProposal is used by the Holder to send a proposal.
func (c *Client) SendProposal(proposal *ProposeCredential, myDID, theirDID string) (string, error) {
	if proposal == nil {
		return "", errEmptyProposal
	}

	proposal.Type = issuecredential.ProposeCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(proposal), myDID, theirDID)
}

// SendRequest is used by the Holder to send a request.
func (c *Client) SendRequest(request *RequestCredential, myDID, theirDID string) (string, error) {
	if request == nil {
		return "", errEmptyRequest
	}

	request.Type = issuecredential.RequestCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(request), myDID, theirDID)
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
// NOTE: For async usage.
func (c *Client) AcceptProposal(piID string, msg *OfferCredential) error {
	return c.service.ActionContinue(piID, WithOfferCredential(msg))
}

// DeclineProposal is used when the Issuer does not want to accept the proposal.
// NOTE: For async usage.
func (c *Client) DeclineProposal(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptOffer is used when the Holder is willing to accept the offer.
func (c *Client) AcceptOffer(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// DeclineOffer is used when the Holder does not want to accept the offer.
// NOTE: For async usage.
func (c *Client) DeclineOffer(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
// NOTE: For async usage. This function can be used only after receiving OfferCredential.
func (c *Client) NegotiateProposal(piID string, msg *ProposeCredential) error {
	return c.service.ActionContinue(piID, WithProposeCredential(msg))
}

// AcceptRequest is used when the Issuer is willing to accept the request.
// NOTE: For async usage.
func (c *Client) AcceptRequest(piID string, msg *IssueCredential) error {
	return c.service.ActionContinue(piID, WithIssueCredential(msg))
}

// DeclineRequest is used when the Issuer does not want to accept the request.
// NOTE: For async usage.
func (c *Client) DeclineRequest(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
// NOTE: For async usage.
func (c *Client) AcceptCredential(piID string, names ...string) error {
	return c.service.ActionContinue(piID, WithFriendlyNames(names...))
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
// NOTE: For async usage.
func (c *Client) DeclineCredential(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptProblemReport accepts problem report action.
func (c *Client) AcceptProblemReport(piID string) error {
	return c.service.ActionContinue(piID, nil)
}

// WithProposeCredential allows providing ProposeCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithProposeCredential(msg *ProposeCredential) issuecredential.Opt {
	origin := issuecredential.ProposeCredential(*msg)

	return issuecredential.WithProposeCredential(&origin)
}

// WithRequestCredential allows providing RequestCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithRequestCredential(msg *RequestCredential) issuecredential.Opt {
	origin := issuecredential.RequestCredential(*msg)

	return issuecredential.WithRequestCredential(&origin)
}

// WithOfferCredential allows providing OfferCredential message
// USAGE: This message should be provided after receiving a ProposeCredential message.
func WithOfferCredential(msg *OfferCredential) issuecredential.Opt {
	origin := issuecredential.OfferCredential(*msg)

	return issuecredential.WithOfferCredential(&origin)
}

// WithIssueCredential allows providing IssueCredential message
// USAGE: This message should be provided after receiving a RequestCredential message.
func WithIssueCredential(msg *IssueCredential) issuecredential.Opt {
	origin := issuecredential.IssueCredential(*msg)

	return issuecredential.WithIssueCredential(&origin)
}

// WithFriendlyNames allows providing names for the credentials.
// USAGE: This function should be used when the Holder receives IssueCredential message.
func WithFriendlyNames(names ...string) issuecredential.Opt {
	return issuecredential.WithFriendlyNames(names...)
}
