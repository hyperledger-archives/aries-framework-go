/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	issuecredentialmiddleware "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/middleware/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// web redirect decorator.
	webRedirectDecorator  = "~web-redirect"
	webRedirectStatusFAIL = "FAIL"
)

var (
	errEmptyOffer    = errors.New("received an empty offer")
	errEmptyProposal = errors.New("received an empty proposal")
	errEmptyRequest  = errors.New("received an empty request")
)

type (
	// OfferCredential is a message sent by the Issuer to the potential Holder,
	// describing the credential they intend to offer and possibly the price they expect to be paid.
	OfferCredential = issuecredential.OfferCredentialParams
	// OfferCredentialV2 is a message sent by the Issuer to the potential Holder,
	// describing the credential they intend to offer and possibly the price they expect to be paid.
	OfferCredentialV2 issuecredential.OfferCredentialV2
	// OfferCredentialV3 is a message sent by the Issuer to the potential Holder,
	// describing the credential they intend to offer and possibly the price they expect to be paid.
	OfferCredentialV3 issuecredential.OfferCredentialV3
	// ProposeCredential is an optional message sent by the potential Holder to the Issuer
	// to initiate the protocol or in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredential = issuecredential.ProposeCredentialParams
	// ProposeCredentialV2 is an optional message sent by the potential Holder to the Issuer
	// to initiate the protocol or in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredentialV2 issuecredential.ProposeCredentialV2
	// ProposeCredentialV3 is an optional message sent by the potential Holder to the Issuer
	// to initiate the protocol or in response to a offer-credential message when the Holder
	// wants some adjustments made to the credential data offered by Issuer.
	ProposeCredentialV3 issuecredential.ProposeCredentialV3
	// RequestCredential is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential. Where circumstances do not require
	// a preceding Offer Credential message (e.g., there is no cost to issuance
	// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
	// this message initiates the protocol.
	RequestCredential = issuecredential.RequestCredentialParams
	// RequestCredentialV2 is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential. Where circumstances do not require
	// a preceding Offer Credential message (e.g., there is no cost to issuance
	// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
	// this message initiates the protocol.
	RequestCredentialV2 issuecredential.RequestCredentialV2
	// RequestCredentialV3 is a message sent by the potential Holder to the Issuer,
	// to request the issuance of a credential. Where circumstances do not require
	// a preceding Offer Credential message (e.g., there is no cost to issuance
	// that the Issuer needs to explain in advance, and there is no need for cryptographic negotiation),
	// this message initiates the protocol.
	RequestCredentialV3 issuecredential.RequestCredentialV3
	// IssueCredential contains as attached payload the credentials being issued and is
	// sent in response to a valid Invitation Credential message.
	IssueCredential = issuecredential.IssueCredentialParams
	// IssueCredentialV2 contains as attached payload the credentials being issued and is
	// sent in response to a valid Invitation Credential message.
	IssueCredentialV2 issuecredential.IssueCredentialV2 //nolint: golint
	// IssueCredentialV3 contains as attached payload the credentials being issued and is
	// sent in response to a valid Invitation Credential message.
	IssueCredentialV3 issuecredential.IssueCredentialV3 //nolint: golint
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
	ActionContinue(piID string, opt ...issuecredential.Opt) error
	ActionStop(piID string, err error, opt ...issuecredential.Opt) error
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
func (c *Client) SendOffer(offer *OfferCredential, conn *connection.Record) (string, error) {
	if offer == nil {
		return "", errEmptyOffer
	}

	var msg service.DIDCommMsg

	switch conn.DIDCommVersion {
	default:
		fallthrough
	case service.V1:
		offer.Type = issuecredential.OfferCredentialMsgTypeV2

		msg = service.NewDIDCommMsgMap(offer.AsV2())
	case service.V2:
		offer.Type = issuecredential.OfferCredentialMsgTypeV3

		msg = service.NewDIDCommMsgMap(offer.AsV3())
	}

	return c.service.HandleOutbound(msg, conn.MyDID, conn.TheirDID)
}

// SendProposal is used by the Holder to send a proposal.
func (c *Client) SendProposal(proposal *ProposeCredential, conn *connection.Record) (string, error) {
	if proposal == nil {
		return "", errEmptyProposal
	}

	var msg service.DIDCommMsg

	switch conn.DIDCommVersion {
	default:
		fallthrough
	case service.V1:
		proposal.Type = issuecredential.ProposeCredentialMsgTypeV2

		msg = service.NewDIDCommMsgMap(proposal.AsV2())
	case service.V2:
		proposal.Type = issuecredential.ProposeCredentialMsgTypeV3

		msg = service.NewDIDCommMsgMap(proposal.AsV3())
	}

	return c.service.HandleOutbound(msg, conn.MyDID, conn.TheirDID)
}

// SendRequest is used by the Holder to send a request.
func (c *Client) SendRequest(request *RequestCredential, conn *connection.Record) (string, error) {
	if request == nil {
		return "", errEmptyRequest
	}

	var msg service.DIDCommMsg

	switch conn.DIDCommVersion {
	default:
		fallthrough
	case service.V1:
		request.Type = issuecredential.RequestCredentialMsgTypeV2

		msg = service.NewDIDCommMsgMap(request.AsV2())
	case service.V2:
		request.Type = issuecredential.RequestCredentialMsgTypeV3

		msg = service.NewDIDCommMsgMap(request.AsV3())
	}

	return c.service.HandleOutbound(msg, conn.MyDID, conn.TheirDID)
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
// NOTE: For async usage.
func (c *Client) AcceptProposal(piID string, msg *OfferCredential) error {
	return c.service.ActionContinue(piID, WithOfferCredential(msg))
}

// AcceptOffer is used when the Holder is willing to accept the offer.
func (c *Client) AcceptOffer(piID string, msg *RequestCredential) error {
	return c.service.ActionContinue(piID, WithRequestCredential(msg))
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

// DeclineProposal is used when the Issuer does not want to accept the proposal.
// NOTE: For async usage.
func (c *Client) DeclineProposal(piID, reason string, options ...IssuerDeclineOptions) error {
	return c.service.ActionStop(piID, errors.New(reason), prepareRedirectProperties(webRedirectStatusFAIL, options...))
}

// DeclineOffer is used when the Holder does not want to accept the offer.
// NOTE: For async usage.
func (c *Client) DeclineOffer(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// DeclineRequest is used when the Issuer does not want to accept the request.
// NOTE: For async usage.
func (c *Client) DeclineRequest(piID, reason string, options ...IssuerDeclineOptions) error {
	return c.service.ActionStop(piID, errors.New(reason), prepareRedirectProperties(webRedirectStatusFAIL, options...))
}

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
// NOTE: For async usage.
func (c *Client) AcceptCredential(piID string, options ...AcceptCredentialOptions) error {
	opts := &acceptCredentialOpts{}

	for _, option := range options {
		option(opts)
	}

	properties := map[string]interface{}{}

	if opts.skipStore {
		properties[issuecredentialmiddleware.SkipCredentialSaveKey] = true
	}

	return c.service.ActionContinue(piID, WithFriendlyNames(opts.names...), issuecredential.WithProperties(properties))
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
// NOTE: For async usage.
func (c *Client) DeclineCredential(piID, reason string) error {
	return c.service.ActionStop(piID, errors.New(reason))
}

// AcceptProblemReport accepts problem report action.
func (c *Client) AcceptProblemReport(piID string) error {
	return c.service.ActionContinue(piID)
}

// WithProposeCredential allows providing ProposeCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithProposeCredential(msg *ProposeCredential) issuecredential.Opt {
	origin := *msg

	return issuecredential.WithProposeCredential(&origin)
}

// WithRequestCredential allows providing RequestCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithRequestCredential(msg *RequestCredential) issuecredential.Opt {
	origin := *msg

	return issuecredential.WithRequestCredential(&origin)
}

// WithOfferCredential allows providing OfferCredential message
// USAGE: This message should be provided after receiving a ProposeCredential message.
func WithOfferCredential(msg *OfferCredential) issuecredential.Opt {
	origin := *msg

	return issuecredential.WithOfferCredential(&origin)
}

// WithIssueCredential allows providing IssueCredential message
// USAGE: This message should be provided after receiving a RequestCredential message.
func WithIssueCredential(msg *IssueCredential) issuecredential.Opt {
	origin := *msg

	return issuecredential.WithIssueCredential(&origin)
}

// WithFriendlyNames allows providing names for the credentials.
// USAGE: This function should be used when the Holder receives IssueCredential message.
func WithFriendlyNames(names ...string) issuecredential.Opt {
	return issuecredential.WithFriendlyNames(names...)
}

// acceptCredentialOpts options for accepting credential in holder.
type acceptCredentialOpts struct {
	names     []string
	skipStore bool
}

// AcceptCredentialOptions is custom option for accepting credential in holder.
type AcceptCredentialOptions func(opts *acceptCredentialOpts)

// AcceptByFriendlyNames option to provide optional friendly names for accepting credentials.
func AcceptByFriendlyNames(names ...string) AcceptCredentialOptions {
	return func(opts *acceptCredentialOpts) {
		opts.names = names
	}
}

// AcceptBySkippingStorage skips storing incoming credential to storage.
func AcceptBySkippingStorage() AcceptCredentialOptions {
	return func(opts *acceptCredentialOpts) {
		opts.skipStore = true
	}
}

// redirectOpts options for web redirect information to holder from issuer.
type redirectOpts struct {
	redirect string
}

// IssuerDeclineOptions is custom option for sending web redirect options to holder.
// https://github.com/hyperledger/aries-rfcs/tree/main/concepts/0700-oob-through-redirect
type IssuerDeclineOptions func(opts *redirectOpts)

// RequestRedirect option to provide optional redirect URL requesting holder to redirect.
func RequestRedirect(url string) IssuerDeclineOptions {
	return func(opts *redirectOpts) {
		opts.redirect = url
	}
}

// create web redirect properties to add ~web-redirect decorator.
func prepareRedirectProperties(status string, options ...IssuerDeclineOptions) issuecredential.Opt {
	properties := map[string]interface{}{}

	opts := &redirectOpts{}

	for _, option := range options {
		option(opts)
	}

	if opts.redirect != "" {
		properties[webRedirectDecorator] = &decorator.WebRedirect{
			Status: status,
			URL:    opts.redirect,
		}
	}

	return issuecredential.WithProperties(properties)
}
