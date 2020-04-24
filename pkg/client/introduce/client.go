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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
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

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
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

// SendProposalWithOOBRequest sends a proposal to the introducee (the client has published an out-of-band request).
func (c *Client) SendProposalWithOOBRequest(req *outofband.Request, recipient *introduce.Recipient) error {
	proposal := introduce.CreateProposal(recipient.To)
	cast := outofbandsvc.Request(*req)

	introduce.WrapWithMetadataPublicOOBRequest(proposal, &cast)

	err := c.service.HandleOutbound(proposal, recipient.MyDID, recipient.TheirDID)

	return err
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share their own out-of-band message.
func (c *Client) SendRequest(to *introduce.PleaseIntroduceTo, myDID, theirDID string) error {
	err := c.service.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type:              introduce.RequestMsgType,
		PleaseIntroduceTo: to,
	}), myDID, theirDID)

	return err
}

// AcceptProposalWithOOBRequest is used when introducee wants to provide an out-of-band request.
// NOTE: For async usage. Introducee can provide this request only after receiving ProposalMsgType
func (c *Client) AcceptProposalWithOOBRequest(piID string, req *outofband.Request) error {
	return c.service.Continue(piID, WithOOBRequest(req))
}

// AcceptRequestWithPublicOOBRequest is used when introducer wants to provide a published out-of-band request.
// NOTE: For async usage. Introducer can provide invitation only after receiving RequestMsgType
func (c *Client) AcceptRequestWithPublicOOBRequest(piID string, req *outofband.Request, to *introduce.To) error {
	return c.service.Continue(piID, WithPublicOOBRequest(req, to))
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
// NOTE: For async usage. Introducer can provide recipients only after receiving RequestMsgType.
func (c *Client) AcceptRequestWithRecipients(piID string, to *introduce.To, recipient *introduce.Recipient) error {
	return c.service.Continue(piID, WithRecipients(to, recipient))
}

// Actions returns unfinished actions for the async usage
func (c *Client) Actions() ([]introduce.Action, error) {
	return c.service.Actions()
}

// WithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
// NOTE: Introducer can provide recipients only after receiving RequestMsgType.
// USAGE: event.Continue(WithRecipients(to, recipient))
func WithRecipients(to *introduce.To, recipient *introduce.Recipient) introduce.Opt {
	return introduce.WithRecipients(to, recipient)
}

// WithPublicOOBRequest is used when introducer wants to provide a published out-of-band request.
// NOTE: Introducer can provide this request only after receiving RequestMsgType
// USAGE: event.Continue(WithPublicOOBRequest(req, to))
func WithPublicOOBRequest(req *outofband.Request, to *introduce.To) introduce.Opt {
	cast := outofbandsvc.Request(*req)
	return introduce.WithPublicOOBRequest(&cast, to)
}

// WithOOBRequest is used when introducee wants to provide invitation.
// NOTE: Introducee can provide invitation only after receiving ProposalMsgType
// USAGE: event.Continue(WithOOBRequest(inv))
func WithOOBRequest(req *outofband.Request) introduce.Opt {
	cast := outofbandsvc.Request(*req)
	return introduce.WithOOBRequest(&cast)
}
