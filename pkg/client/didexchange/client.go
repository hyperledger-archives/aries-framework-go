/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to didexchange api
type Client struct {
	didexchangeSvc dispatcher.Service
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}
	didexchangeSvc, ok := svc.(dispatcher.Service)
	if !ok {
		return nil, errors.New("cast service to DIDExchange Service failed")
	}
	return &Client{didexchangeSvc: didexchangeSvc}, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation() (*InvitationRequest, error) {
	return &InvitationRequest{Invitation: &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           "agent",                        // TODO get the value from config #175
		RecipientKeys:   nil,                            // TODO #178
		ServiceEndpoint: "https://example.com/endpoint", // TODO get the value from config #175
	}}, nil
}
