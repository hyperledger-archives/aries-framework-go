/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to didexchange api
type Client struct {
	didexchangeSvc *didexchange.Service
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}
	didexchangeSvc, ok := svc.(*didexchange.Service)
	if !ok {
		return nil, errors.New("cast service to didexchange.Service failed")
	}
	return &Client{didexchangeSvc: didexchangeSvc}, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation() (*didexchange.InvitationRequest, error) {
	return c.didexchangeSvc.CreateInvitation()
}
