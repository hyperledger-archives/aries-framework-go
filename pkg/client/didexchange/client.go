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
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// ConnectionID connection id is created to retriever connection record from db
	ConnectionID = didexchange.ConnectionID
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = didexchange.InvitationMsgType
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = didexchange.RequestMsgType
	// ResponseMsgType defines the did-exchange response message type.
	ResponseMsgType = didexchange.ResponseMsgType
	// AckMsgType defines the did-exchange ack message type.
	AckMsgType = didexchange.AckMsgType
)

// ErrConnectionNotFound is returned when connection not found
var ErrConnectionNotFound = errors.New("connection not found")

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	InboundTransportEndpoint() string
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
}

// Client enable access to didexchange api
type Client struct {
	service.Event
	didexchangeSvc           protocolService
	kms                      kms.KeyManager
	inboundTransportEndpoint string
	connectionStore          *didexchange.ConnectionRecorder
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.DIDComm

	// Accepts/Approves exchange request
	AcceptExchangeRequest(connectionID string) error
}

// New return new instance of didexchange client
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	didexchangeSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to DIDExchange Service failed")
	}

	store, err := ctx.StorageProvider().OpenStore(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	transientStore, err := ctx.TransientStorageProvider().OpenStore(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	return &Client{
		Event:                    didexchangeSvc,
		didexchangeSvc:           didexchangeSvc,
		kms:                      ctx.KMS(),
		inboundTransportEndpoint: ctx.InboundTransportEndpoint(),
		connectionStore:          didexchange.NewConnectionRecorder(transientStore, store),
	}, nil
}

// CreateInvitation create invitation
// TODO 'alias' should be passed as arg and persisted with connection record [Issue #623]
func (c *Client) CreateInvitation(label string) (*Invitation, error) {
	_, sigPubKey, err := c.kms.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	invitation := &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
		RecipientKeys:   []string{sigPubKey},
		ServiceEndpoint: c.inboundTransportEndpoint,
		Type:            didexchange.InvitationMsgType,
	}

	err = c.connectionStore.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	return &Invitation{invitation}, nil
}

// CreateInvitationWithDID creates invitation with specified public DID
func (c *Client) CreateInvitationWithDID(label, did string) (*Invitation, error) {
	invitation := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Label: label,
		DID:   did,
		Type:  didexchange.InvitationMsgType,
	}

	err := c.connectionStore.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation with DID: %w", err)
	}

	return &Invitation{invitation}, nil
}

// HandleInvitation handle incoming invitation and returns the connectionID.
func (c *Client) HandleInvitation(invitation *Invitation) (string, error) {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return "", fmt.Errorf("failed marshal invitation: %w", err)
	}

	msg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return "", fmt.Errorf("failed to create DIDCommMsg: %w", err)
	}

	connectionID, err := c.didexchangeSvc.HandleInbound(msg)
	if err != nil {
		return "", fmt.Errorf("failed from didexchange service handle: %w", err)
	}

	return connectionID, nil
}

// AcceptExchangeRequest accepts/approves exchange request.
func (c *Client) AcceptExchangeRequest(connectionID string) error {
	if err := c.didexchangeSvc.AcceptExchangeRequest(connectionID); err != nil {
		return fmt.Errorf("did exchange client - accept exchange request: %w", err)
	}

	return nil
}

// QueryConnections queries connections matching given parameters
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*Connection, error) {
	// TODO query all connections from all criteria [Issue #655]
	// TODO also results needs to be paged  [Issue #655]
	records, err := c.connectionStore.QueryConnectionRecords()
	if err != nil {
		return nil, fmt.Errorf("failed query connections: %w", err)
	}

	var result []*Connection

	for _, record := range records {
		if request.State != "" && request.State != record.State {
			continue
		}

		result = append(result, &Connection{ConnectionRecord: record})
	}

	return result, nil
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
		conn,
	}, nil
}

// GetConnectionAtState fetches connection record for connection id at particular state.
func (c *Client) GetConnectionAtState(connectionID, stateID string) (*Connection, error) {
	conn, err := c.connectionStore.GetConnectionRecordAtState(connectionID, stateID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrConnectionNotFound
		}

		return nil, fmt.Errorf("cannot fetch state from store: connectionid=%s err=%s", connectionID, err)
	}

	return &Connection{
		conn,
	}, nil
}

// RemoveConnection removes connection record for given id
func (c *Client) RemoveConnection(id string) error {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/553 RemoveConnection from did exchange service
	return nil
}
