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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

var logger = log.New("aries-framework/didexchange-client")

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
	didexchangeSvc           dispatcher.DIDCommService
	wallet                   wallet.Crypto
	inboundTransportEndpoint string
	actionCh                 chan dispatcher.DIDCommAction
	msgCh                    chan dispatcher.StateMsg
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}
	didexchangeSvc, ok := svc.(dispatcher.DIDCommService)
	if !ok {
		return nil, errors.New("cast service to DIDExchange Service failed")
	}
	c := &Client{
		didexchangeSvc:           didexchangeSvc,
		wallet:                   ctx.CryptoWallet(),
		inboundTransportEndpoint: ctx.InboundTransportEndpoint(),
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		actionCh: make(chan dispatcher.DIDCommAction, 10),
		msgCh:    make(chan dispatcher.StateMsg, 10),
	}

	err = c.startServiceEventListener()
	if err != nil {
		return nil, fmt.Errorf("service event listener startup failed: %w", err)
	}

	return c, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation(label string) (*didexchange.Invitation, error) {
	verKey, err := c.wallet.CreateKey()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	return &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
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

// startServiceEventListener listens to action and message events from DID Exchange service.
func (c *Client) startServiceEventListener() error {
	// register the action event channel
	err := c.didexchangeSvc.RegisterActionEvent(c.actionCh)
	if err != nil {
		return fmt.Errorf("didexchange action event registration failed: %w", err)
	}

	// register the message event channel
	err = c.didexchangeSvc.RegisterMsgEvent(c.msgCh)
	if err != nil {
		return fmt.Errorf("didexchange message event registration failed: %w", err)
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/199 - Generate Client events
	// for now, auto execute the actions
	go func() {
		err := didexchange.AutoExecuteActionEvent(c.actionCh)
		if err != nil {
			logger.Errorf("auto action event execution failed: %s", err)
		}
	}()

	go func() {
		for e := range c.msgCh {
			// TODO https://github.com/hyperledger/aries-framework-go/issues/199 - Generate Client events
			// for now, log the messages
			logger.Infof("message event received : type=%s", e.Type)
		}
	}()

	return nil
}
