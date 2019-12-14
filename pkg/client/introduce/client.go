/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const invitationEnvelopePrefix = "invitation_envelope_"

var logger = log.New("aries-framework/introduce/client")

// Provider contains dependencies for the introduce protocol and is typically created by using aries.Context()
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
}

// Client enable access to introduce API
type Client struct {
	service.Event
	service    service.DIDComm
	store      storage.Store
	defaultInv *didexchange.Invitation
	newUUID    func() string
}

// New return new instance of introduce client
func New(ctx Provider, inv *didexchange.Invitation) (*Client, error) {
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
		Event:      introduceSvc,
		service:    introduceSvc,
		store:      store,
		defaultInv: inv,
		newUUID:    func() string { return uuid.New().String() },
	}, nil
}

// InvitationEnvelope is a helper function that returns the dependency needed for the
// service to proceed with the protocol. Dependency should be passed to the service through `Continue` function.
// The function should never return an error, instead of error we provide the callable interface
// and the state machine will act according to the provided data.
// Dependency is populated after executing the following functions:
//  - SendProposal
//  - SendProposalWithInvitation
//  - HandleRequest
//  - HandleRequestWithInvitation
// usage: e.Continue(c.InvitationEnvelope(threadID))
func (c *Client) InvitationEnvelope(thID string) *InvitationEnvelope {
	opts, err := c.getInvitationEnvelope(thID)

	if errors.Is(err, storage.ErrDataNotFound) {
		return &InvitationEnvelope{Inv: c.defaultInv}
	}

	if err != nil {
		logger.Errorf("invitation envelope: %v", err)
		return &InvitationEnvelope{}
	}

	return opts
}

// SendProposal sends proposal to introducees (the client does not have a public Invitation)
func (c *Client) SendProposal(recipient1, recipient2 *introduce.Recipient) error {
	return c.sendProposal(InvitationEnvelope{
		Recps: []*introduce.Recipient{recipient1, recipient2},
	})
}

// SendProposalWithInvitation sends proposal to introducee (the client has a public Invitation)
func (c *Client) SendProposalWithInvitation(inv *didexchange.Invitation, recipient *introduce.Recipient) error {
	return c.sendProposal(InvitationEnvelope{
		Inv:   inv,
		Recps: []*introduce.Recipient{recipient},
	})
}

// SendRequest sends a request
// sending a request means that introducee is willing to share its invitation
func (c *Client) SendRequest(myDID, theirDID string) error {
	return c.handleOutbound(&introduce.Request{
		Type: introduce.RequestMsgType,
		ID:   c.newUUID(),
	}, InvitationEnvelope{
		Recps: []*introduce.Recipient{{MyDID: myDID, TheirDID: theirDID}},
	})
}

// HandleRequest is a helper function to prepare the right protocol dependency interface
// It can be executed after receiving a Request action message (the client does not have a public Invitation)
func (c *Client) HandleRequest(msg service.DIDCommMsg, to *introduce.To, recipient *introduce.Recipient) error {
	thID, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("handle request threadID: %w", err)
	}

	return c.saveInvitationEnvelope(thID, InvitationEnvelope{
		Recps: []*introduce.Recipient{{To: to}, recipient},
	})
}

// HandleRequestWithInvitation is a helper function to prepare the right protocol dependency interface
// It can be executed after receiving a Request action message (the client has a public Invitation)
// nolint: lll
func (c *Client) HandleRequestWithInvitation(msg service.DIDCommMsg, inv *didexchange.Invitation, to *introduce.To) error {
	thID, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("handle request with invitation threadID: %w", err)
	}

	return c.saveInvitationEnvelope(thID, InvitationEnvelope{
		Inv:   inv,
		Recps: []*introduce.Recipient{{To: to}},
	})
}

func (c *Client) handleOutbound(msg interface{}, o InvitationEnvelope) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal outbound msg: %w", err)
	}

	didMsg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return fmt.Errorf("new outbound DIDCommMsg msg: %w", err)
	}

	thID, err := didMsg.ThreadID()
	if err != nil {
		return fmt.Errorf("outbound threadID: %w", err)
	}

	if err := c.saveInvitationEnvelope(thID, o); err != nil {
		return err
	}

	return c.service.HandleOutbound(didMsg, o.Recps[0].MyDID, o.Recps[0].MyDID)
}

// InvitationEnvelope keeps the information needed for sending a proposal
type InvitationEnvelope struct {
	// Invitation must be set when we have a public Invitation
	Inv *didexchange.Invitation `json:"invitation,omitempty"`
	// Recipients contain one or two elements
	// one element - for the public Invitation, otherwise two elements
	Recps []*introduce.Recipient `json:"recipients,omitempty"`
}

// Invitation returns an Invitation needed for the service (state machine depends on it)
func (o *InvitationEnvelope) Invitation() *didexchange.Invitation {
	return o.Inv
}

// Recipients returns data needed for the service (state machine depends on it)
func (o *InvitationEnvelope) Recipients() []*introduce.Recipient {
	return o.Recps
}

// sendProposal sends proposal
func (c *Client) sendProposal(o InvitationEnvelope) error {
	return c.handleOutbound(&introduce.Proposal{
		Type: introduce.ProposalMsgType,
		ID:   c.newUUID(),
		To:   o.Recps[0].To,
	}, o)
}

func (c *Client) saveInvitationEnvelope(thID string, o InvitationEnvelope) error {
	data, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("marshal invitation envelope: %w", err)
	}

	return c.store.Put(invitationEnvelopeKey(thID), data)
}

func (c *Client) getInvitationEnvelope(thID string) (*InvitationEnvelope, error) {
	data, err := c.store.Get(invitationEnvelopeKey(thID))
	if err != nil {
		return nil, fmt.Errorf("get invitation envelope: %w", err)
	}

	var o *InvitationEnvelope
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("unmarshal invitation envelope: %w", err)
	}

	return o, nil
}

func invitationEnvelopeKey(thID string) string {
	return invitationEnvelopePrefix + thID
}
