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

// Provider contains dependencies for the issuecredential protocol and is typically created by using aries.Context()
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

// Client enable access to issuecredential API
type Client struct {
	service.Event
	service ProtocolService
}

// New return new instance of the issuecredential client
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

// Actions returns unfinished actions for the async usage
func (c *Client) Actions() ([]issuecredential.Action, error) {
	return c.service.Actions()
}

// SendOffer is used by the Issuer to send an offer.
func (c *Client) SendOffer(offer *issuecredential.OfferCredential, myDID, theirDID string) error {
	if offer == nil {
		return errEmptyOffer
	}

	offer.Type = issuecredential.OfferCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(offer), myDID, theirDID)
}

// SendProposal is used by the Holder to send a proposal.
func (c *Client) SendProposal(proposal *issuecredential.ProposeCredential, myDID, theirDID string) error {
	if proposal == nil {
		return errEmptyProposal
	}

	proposal.Type = issuecredential.ProposeCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(proposal), myDID, theirDID)
}

// SendRequest is used by the Holder to send a request.
func (c *Client) SendRequest(request *issuecredential.RequestCredential, myDID, theirDID string) error {
	if request == nil {
		return errEmptyRequest
	}

	request.Type = issuecredential.RequestCredentialMsgType

	return c.service.HandleOutbound(service.NewDIDCommMsgMap(request), myDID, theirDID)
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
// NOTE: For async usage.
func (c *Client) AcceptProposal(piID string, msg *issuecredential.OfferCredential) error {
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
// NOTE: For async usage. This function can be used only after receiving OfferCredential
func (c *Client) NegotiateProposal(piID string, msg *issuecredential.ProposeCredential) error {
	return c.service.ActionContinue(piID, WithProposeCredential(msg))
}

// AcceptRequest is used when the Issuer is willing to accept the request.
// NOTE: For async usage.
func (c *Client) AcceptRequest(piID string, msg *issuecredential.IssueCredential) error {
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

// WithProposeCredential allows providing ProposeCredential message
// USAGE: This message should be provided after receiving an OfferCredential message
func WithProposeCredential(msg *issuecredential.ProposeCredential) issuecredential.Opt {
	return issuecredential.WithProposeCredential(msg)
}

// WithOfferCredential allows providing OfferCredential message
// USAGE: This message should be provided after receiving a ProposeCredential message
func WithOfferCredential(msg *issuecredential.OfferCredential) issuecredential.Opt {
	return issuecredential.WithOfferCredential(msg)
}

// WithIssueCredential allows providing IssueCredential message
// USAGE: This message should be provided after receiving a RequestCredential message
func WithIssueCredential(msg *issuecredential.IssueCredential) issuecredential.Opt {
	return issuecredential.WithIssueCredential(msg)
}

// WithFriendlyNames allows providing names for the credentials.
// USAGE: This function should be used when the Holder receives IssueCredential message
func WithFriendlyNames(names ...string) issuecredential.Opt {
	return issuecredential.WithFriendlyNames(names...)
}
