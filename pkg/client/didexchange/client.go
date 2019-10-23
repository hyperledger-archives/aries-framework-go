/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

const (
	// ConnectionID connection id is created to retriever connection record from db
	ConnectionID = didexchange.ConnectionID
	// InvitationID invitation id is created in invitation request
	InvitationID = didexchange.InvitationID
)

// ErrConnectionNotFound is returned when connection not found
var ErrConnectionNotFound = errors.New("connection not found")

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	CryptoWallet() wallet.Crypto
	InboundTransportEndpoint() string
	StorageProvider() storage.Provider
}

// Client enable access to didexchange api
type Client struct {
	service.Action
	service.Message
	didexchangeSvc           service.DIDComm
	wallet                   wallet.Crypto
	inboundTransportEndpoint string
	actionCh                 chan service.DIDCommAction
	msgCh                    chan service.StateMsg
	connectionStore          *didexchange.ConnectionRecorder
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	didexchangeSvc, ok := svc.(service.DIDComm)
	if !ok {
		return nil, errors.New("cast service to DIDExchange Service failed")
	}

	store, err := ctx.StorageProvider().OpenStore(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	c := &Client{
		didexchangeSvc:           didexchangeSvc,
		wallet:                   ctx.CryptoWallet(),
		inboundTransportEndpoint: ctx.InboundTransportEndpoint(),
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		actionCh:        make(chan service.DIDCommAction, 10),
		msgCh:           make(chan service.StateMsg, 10),
		connectionStore: didexchange.NewConnectionRecorder(store),
	}

	// register the action event channel
	err = c.didexchangeSvc.RegisterActionEvent(c.actionCh)
	if err != nil {
		return nil, fmt.Errorf("didexchange action event registration: %w", err)
	}

	// register the message event channel
	err = c.didexchangeSvc.RegisterMsgEvent(c.msgCh)
	if err != nil {
		return nil, fmt.Errorf("didexchange message event registration: %w", err)
	}

	// start listening for action/message events
	go c.startServiceEventListener()

	return c, nil
}

// CreateInvitation create invitation
func (c *Client) CreateInvitation(label string) (*Invitation, error) {
	verKey, err := c.wallet.CreateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	invitation := &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
		RecipientKeys:   []string{verKey},
		ServiceEndpoint: c.inboundTransportEndpoint,
		Type:            didexchange.ConnectionInvite,
	}

	err = c.connectionStore.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	return &Invitation{*invitation}, nil
}

// CreateInvitationWithDID creates invitation with specified public DID
func (c *Client) CreateInvitationWithDID(label, did string) (*Invitation, error) {
	invitation := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Label: label,
		DID:   did,
		Type:  didexchange.ConnectionInvite,
	}

	err := c.connectionStore.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation with DID: %w", err)
	}

	return &Invitation{*invitation}, nil
}

// HandleInvitation handle incoming invitation
func (c *Client) HandleInvitation(invitation *Invitation) error {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return fmt.Errorf("failed marshal invitation: %w", err)
	}

	msg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return fmt.Errorf("failed to create DIDCommMsg: %w", err)
	}

	if err = c.didexchangeSvc.HandleInbound(msg); err != nil {
		return fmt.Errorf("failed from didexchange service handle: %w", err)
	}
	return nil
}

// QueryConnections queries connections matching given parameters
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*Connection, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/429 query all connections from did exchange service
	return []*Connection{
		{didexchange.ConnectionRecord{ConnectionID: uuid.New().String()}},
		{didexchange.ConnectionRecord{ConnectionID: uuid.New().String()}},
	}, nil
}

// GetConnection fetches single connection record for given id
func (c *Client) GetConnection(connectionID string) (*Connection, error) {
	conn, err := c.connectionStore.GetConnectionRecord(connectionID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrConnectionNotFound
		}
		return nil, fmt.Errorf("cannot fetch state from store: connectionid=%s err=%s", connectionID, err)
	}
	return &Connection{
		didexchange.ConnectionRecord{ConnectionID: connectionID, State: conn.State},
	}, nil
}

// RemoveConnection removes connection record for given id
func (c *Client) RemoveConnection(id string) error {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/553 RemoveConnection from did exchange service
	return nil
}

// startServiceEventListener listens to action and message events from DID Exchange service.
func (c *Client) startServiceEventListener() {
	// listen for action event and message events
	for {
		select {
		case e := <-c.actionCh:
			// assigned to var as lint fails with : Using a reference for the variable on range scope (scopelint)
			c.ActionEvent() <- e
		case e := <-c.msgCh:
			// assigned to var as lint fails with : Using a reference for the variable on range scope (scopelint)
			c.handleMessageEvent(e)
		}
	}
}

func (c *Client) handleMessageEvent(msg service.StateMsg) {
	for _, handler := range c.MsgEvents() {
		handler <- msg
	}
}
