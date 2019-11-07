/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider contains dependencies for the introduce protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
}

// Client enable access to introduce API
type Client struct {
	service.Event
	service service.DIDComm
	store   storage.Store
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

	store, err := ctx.StorageProvider().OpenStore(introduce.Introduce)
	if err != nil {
		return nil, err
	}

	return &Client{
		Event:   introduceSvc,
		service: introduceSvc,
		store:   store,
	}, nil
}

// SendProposal sends proposal to introducees
func (c *Client) SendProposal(dest1, dest2 *service.Destination) error {
	return c.sendProposal(options{
		Destinations: []*service.Destination{dest1, dest2},
	})
}

// SendProposalWithInvitation sends proposal to introducee
// executes when the client has a public Invitation
func (c *Client) SendProposalWithInvitation(inv *didexchange.Invitation, dest *service.Destination) error {
	return c.sendProposal(options{
		Invitation:   inv,
		Destinations: []*service.Destination{dest},
	})
}

// SendRequest sends request
// sending a request means that introducee is willing to share its invitation
func (c *Client) SendRequest(dest *service.Destination) error {
	return c.handleOutbound(&introduce.Request{
		Type: introduce.RequestMsgType,
		ID:   uuid.New().String(),
	})
}

// HandleRequest executes after receiving a request (the client does not have a public Invitation)
func (c *Client) HandleRequest(dest1, dest2 *service.Destination) error {
	return c.sendProposal(options{
		Destinations: []*service.Destination{dest1, dest2},
	})
}

// HandleRequestWithInvitation executes after receiving a request when the client has a public Invitation
func (c *Client) HandleRequestWithInvitation(inv *didexchange.Invitation, dest *service.Destination) error {
	return c.sendProposal(options{
		Invitation:   inv,
		Destinations: []*service.Destination{dest},
	})
}

func (c *Client) handleOutbound(msg interface{}) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	didMsg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return err
	}

	return c.service.HandleOutbound(didMsg, &service.Destination{})
}

// options keeps the information needed for sending a proposal
type options struct {
	// Invitation must be set when we have a public Invitation
	Invitation *didexchange.Invitation
	// Destinations contain one or two elements
	// one element - for a public Invitation, otherwise two elements
	Destinations []*service.Destination
}

// sendProposal sends proposal
// the function may receive an `Invitation` or <nil> (e.g options.Invitation)
// if the invitation is not <nil> it means we have a public invitation.
// Destinations (e.g options.Destinations) should have one or two values, if destinations have only one value it means
// that it is public invitation (an invitation `options.Invitation` is required), otherwise if destinations have two
// values, it means we do not have a public invitation (we will wait for it from one of introducees)
// Usage:
//  Sends public invitation to the destination
// 	sendProposal(&options{
// 		Invitation: invitation,
// 		Destinations: []*service.Destination{
// 			destination,
// 		},
// 	})
// 	Forwards an invitation from one introducee to another
// 	sendProposal(&options{
// 		Destinations: []*service.Destination{
// 			destination1,
// 			destination2,
// 		},
// 	})
func (c *Client) sendProposal(_ options) error {
	return c.handleOutbound(&introduce.Proposal{
		Type: introduce.ProposalMsgType,
		ID:   uuid.New().String(),
	})
}
