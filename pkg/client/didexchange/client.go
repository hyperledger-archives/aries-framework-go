/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	CryptoWallet() wallet.Crypto
	InboundTransportEndpoint() string
}

// Client enable access to didexchange api
// TODO add support for Accept Exchange Request & Accept Invitation
//  using events & callback (#198 & #238)
type Client struct {
	didexchangeSvc           dispatcher.Service
	wallet                   wallet.Crypto
	inboundTransportEndpoint string
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
	return &Client{didexchangeSvc: didexchangeSvc, wallet: ctx.CryptoWallet(), inboundTransportEndpoint: ctx.InboundTransportEndpoint()}, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation() (*didexchange.Invitation, error) {
	verKey, err := c.wallet.CreateKey()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	return &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           "agent", // TODO pass label as argument
		RecipientKeys:   []string{verKey},
		ServiceEndpoint: c.inboundTransportEndpoint,
		Type:            didexchange.ConnectionInvite,
	}, nil
}

// HandleInvitation handle incoming invitation
func (c *Client) HandleInvitation(invitation *didexchange.Invitation) error {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed marshal invitation: %w", err)
	}
	if err = c.didexchangeSvc.Handle(dispatcher.DIDCommMsg{Type: invitation.Type, Payload: payload}); err != nil {
		return fmt.Errorf("failed from didexchange service handle: %w", err)
	}
	return nil
}

// QueryConnections queries connections matching given parameters
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*QueryConnectionResult, error) {
	// TODO sample response, to be implemented as part of #226
	return []*QueryConnectionResult{
		{ConnectionID: uuid.New().String(), CreatedTime: time.Now()},
		{ConnectionID: uuid.New().String(), CreatedTime: time.Now()},
	}, nil
}

// QueryConnectionByID fetches single connection record for given id
func (c *Client) QueryConnectionByID(id string) (*QueryConnectionResult, error) {
	// TODO sample response, to be implemented as part of #226
	return &QueryConnectionResult{
		ConnectionID: uuid.New().String(), CreatedTime: time.Now(),
	}, nil
}

// RemoveConnection removes connection record for given id
func (c *Client) RemoveConnection(id string) error {
	// TODO sample response, to be implemented as part of #226
	return nil
}
