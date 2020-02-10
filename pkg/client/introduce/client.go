/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
)

// Provider contains dependencies for the introduce protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to introduce API
type Client struct {
	service.Event
	service service.DIDComm
}

// New return new instance of introduce client
func New(ctx Provider) (*Client, error) {
	svc, err := ctx.Service(introduce.Introduce)
	if err != nil {
		return nil, err
	}

	introduceSvc, ok := svc.(service.DIDComm)
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
	ctxID := uuid.New().String()

	err := c.service.HandleOutbound(
		introduce.WrapWithMetadataContextID(
			introduce.CreateProposal(recipient1.To), ctxID,
		),
		recipient1.MyDID, recipient1.TheirDID,
	)

	if err != nil {
		return fmt.Errorf("handle outbound: %w", err)
	}

	return c.service.HandleOutbound(
		introduce.WrapWithMetadataContextID(
			introduce.CreateProposal(recipient2.To), ctxID,
		),
		recipient2.MyDID, recipient2.TheirDID,
	)
}

// SendProposalWithInvitation sends a proposal to the introducee (the client has a public Invitation).
func (c *Client) SendProposalWithInvitation(inv *didexchange.Invitation, recipient *introduce.Recipient) error {
	return c.service.HandleOutbound(
		introduce.WrapWithMetadataPublicInvitation(
			introduce.CreateProposal(recipient.To), inv,
		),
		recipient.MyDID, recipient.TheirDID,
	)
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share its invitation.
func (c *Client) SendRequest(to *introduce.PleaseIntroduceTo, myDID, theirDID string) error {
	return c.service.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type:              introduce.RequestMsgType,
		PleaseIntroduceTo: to,
	}), myDID, theirDID)
}

// WithRecipients is used when the introducer does not have a public invitation
// but he is willing to introduce agents to each other.
// NOTE: Introducer can provide recipients only after receiving RequestMsgType.
// USAGE: event.Continue(WithRecipients(to, recipient))
var WithRecipients = introduce.WithRecipients // nolint: gochecknoglobals

// WithPublicInvitation is used when introducer wants to provide public invitation.
// NOTE: Introducer can provide invitation only after receiving RequestMsgType
// USAGE: event.Continue(WithPublicInvitation(inv, to))
var WithPublicInvitation = introduce.WithPublicInvitation // nolint: gochecknoglobals

// WithInvitation is used when introducee wants to provide invitation.
// NOTE: Introducee can provide invitation only after receiving ProposalMsgType
// USAGE: event.Continue(WithInvitation(inv))
var WithInvitation = introduce.WithInvitation // nolint: gochecknoglobals
