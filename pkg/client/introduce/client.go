/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
)

// Provider contains dependencies for the introduce protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
}

// ProtocolService defines the introduce service.
type ProtocolService interface {
	service.DIDComm
	Continue(piID string, opt introduce.Opt) error
	Actions() ([]introduce.Action, error)
}

// Client enable access to introduce API
type Client struct {
	service.Event
	service ProtocolService
}

// New return new instance of introduce client
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

// SendProposal sends a proposal to the introducees (the client does not have a public Invitation).
func (c *Client) SendProposal(recipient1, recipient2 *introduce.Recipient) error {
	proposal1 := introduce.CreateProposal(recipient1.To)
	proposal2 := introduce.CreateProposal(recipient2.To)

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	err := c.service.HandleOutbound(proposal1, recipient1.MyDID, recipient1.TheirDID)
	if err != nil {
		return fmt.Errorf("handle outbound: %w", err)
	}

	err = c.service.HandleOutbound(proposal2, recipient2.MyDID, recipient2.TheirDID)

	return err
}

// SendProposalWithInvitation sends a proposal to the introducee (the client has a public Invitation).
func (c *Client) SendProposalWithInvitation(inv *didexchange.Invitation, recipient *introduce.Recipient) error {
	proposal := introduce.CreateProposal(recipient.To)

	introduce.WrapWithMetadataPublicInvitation(proposal, inv.Invitation)

	err := c.service.HandleOutbound(proposal, recipient.MyDID, recipient.TheirDID)

	return err
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share its invitation.
func (c *Client) SendRequest(to *introduce.PleaseIntroduceTo, myDID, theirDID string) error {
	err := c.service.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type:              introduce.RequestMsgType,
		PleaseIntroduceTo: to,
	}), myDID, theirDID)

	return err
}

// AcceptProposal is used when introducee wants to provide invitation.
// NOTE: For async usage. Introducee can provide invitation only after receiving ProposalMsgType
func (c *Client) AcceptProposal(piID string, inv *didexchange.Invitation) error {
	return c.service.Continue(piID, WithInvitation(inv))
}

// AcceptRequestWithPublicInvitation is used when introducer wants to provide public invitation.
// NOTE: For async usage. Introducer can provide invitation only after receiving RequestMsgType
func (c *Client) AcceptRequestWithPublicInvitation(piID string, inv *didexchange.Invitation, to *introduce.To) error {
	return c.service.Continue(piID, WithPublicInvitation(inv, to))
}

// AcceptRequestWithRecipients is used when the introducer does not have a public invitation
// but he is willing to introduce agents to each other.
// NOTE: For async usage. Introducer can provide recipients only after receiving RequestMsgType.
func (c *Client) AcceptRequestWithRecipients(piID string, to *introduce.To, recipient *introduce.Recipient) error {
	return c.service.Continue(piID, WithRecipients(to, recipient))
}

// Actions returns unfinished actions for the async usage
func (c *Client) Actions() ([]introduce.Action, error) {
	return c.service.Actions()
}

// WithRecipients is used when the introducer does not have a public invitation
// but he is willing to introduce agents to each other.
// NOTE: Introducer can provide recipients only after receiving RequestMsgType.
// USAGE: event.Continue(WithRecipients(to, recipient))
func WithRecipients(to *introduce.To, recipient *introduce.Recipient) introduce.Opt {
	return introduce.WithRecipients(to, recipient)
}

// WithPublicInvitation is used when introducer wants to provide public invitation.
// NOTE: Introducer can provide invitation only after receiving RequestMsgType
// USAGE: event.Continue(WithPublicInvitation(inv, to))
func WithPublicInvitation(inv *didexchange.Invitation, to *introduce.To) introduce.Opt {
	return introduce.WithPublicInvitation(inv.Invitation, to)
}

// WithInvitation is used when introducee wants to provide invitation.
// NOTE: Introducee can provide invitation only after receiving ProposalMsgType
// USAGE: event.Continue(WithInvitation(inv))
func WithInvitation(inv *didexchange.Invitation) introduce.Opt {
	return introduce.WithInvitation(inv.Invitation)
}
