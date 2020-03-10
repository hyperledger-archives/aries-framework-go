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
