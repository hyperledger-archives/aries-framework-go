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

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
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
	DIDConnectionStore() didconnection.Store
}

// Client enable access to didexchange api
type Client struct {
	service.Event
	didexchangeSvc           protocolService
	kms                      kms.KeyManager
	inboundTransportEndpoint string
	connectionStore          *connectionstore.ConnectionLookup
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.DIDComm

	// Accepts/Approves exchange request
	AcceptExchangeRequest(connectionID, publicDID, label string) error

	// Accepts/Approves exchange invitation
	AcceptInvitation(connectionID, publicDID, label string) error

	// CreateImplicitInvitation creates implicit invitation. Inviter DID is required, invitee DID is optional.
	// If invitee DID is not provided new peer DID will be created for implicit invitation exchange request.
	CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel, inviteeDID string) (string, error)

	// SaveInvitation saves given invitation in did-exchange service connection store
	// TODO to be removed as part of [Issue #1021]
	SaveInvitation(invitation *didexchange.Invitation) error
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

	connectionStore, err := connectionstore.NewConnectionLookup(ctx)
	if err != nil {
		return nil, err
	}

	return &Client{
		Event:                    didexchangeSvc,
		didexchangeSvc:           didexchangeSvc,
		kms:                      ctx.KMS(),
		inboundTransportEndpoint: ctx.InboundTransportEndpoint(),
		connectionStore:          connectionStore,
	}, nil
}

// CreateInvitation creates an invitation. New key pair will be generated and base58 encoded public key will be
// used as basis for invitation. This invitation will be stored so client can cross reference this invitation during
// did exchange protocol
func (c *Client) CreateInvitation(label string) (*Invitation, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/623 'alias' should be passed as arg and persisted
	//  with connection record
	_, sigPubKey, err := c.kms.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	invitation := &didexchange.Invitation{
		Header: service.Header{
			ID:   uuid.New().String(),
			Type: didexchange.InvitationMsgType,
		},
		Label:           label,
		RecipientKeys:   []string{sigPubKey},
		ServiceEndpoint: c.inboundTransportEndpoint,
	}

	err = c.didexchangeSvc.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	return &Invitation{invitation}, nil
}

// CreateInvitationWithDID creates an invitation with specified public DID. This invitation will be stored
// so client can cross reference this invitation during did exchange protocol
func (c *Client) CreateInvitationWithDID(label, did string) (*Invitation, error) {
	invitation := &didexchange.Invitation{
		Header: service.Header{
			ID:   uuid.New().String(),
			Type: didexchange.InvitationMsgType,
		},
		Label: label,
		DID:   did,
	}

	err := c.didexchangeSvc.SaveInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation with DID: %w", err)
	}

	return &Invitation{invitation}, nil
}

// HandleInvitation handle incoming invitation and returns the connectionID that can be used to query the state
// of did exchange protocol. Upon successful completion of did exchange protocol connection details will be used
// for securing communication between agents.
func (c *Client) HandleInvitation(invitation *Invitation) (string, error) {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return "", fmt.Errorf("failed marshal invitation: %w", err)
	}

	msg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return "", fmt.Errorf("failed to create DIDCommMsg: %w", err)
	}

	connectionID, err := c.didexchangeSvc.HandleInbound(msg, "", "")
	if err != nil {
		return "", fmt.Errorf("failed from didexchange service handle: %w", err)
	}

	return connectionID, nil
}

// TODO https://github.com/hyperledger/aries-framework-go/issues/754 - e.Continue v Explicit API call for action events

// AcceptInvitation accepts/approves exchange invitation. This call is not used if auto execute is setup
// for this client (see package example for more details about how to setup auto execute)
func (c *Client) AcceptInvitation(connectionID, publicDID, label string) error {
	if err := c.didexchangeSvc.AcceptInvitation(connectionID, publicDID, label); err != nil {
		return fmt.Errorf("did exchange client - accept exchange invitation: %w", err)
	}

	return nil
}

// AcceptExchangeRequest accepts/approves exchange request. This call is not used if auto execute is setup
// for this client (see package example for more details about how to setup auto execute)
func (c *Client) AcceptExchangeRequest(connectionID, publicDID, label string) error {
	if err := c.didexchangeSvc.AcceptExchangeRequest(connectionID, publicDID, label); err != nil {
		return fmt.Errorf("did exchange client - accept exchange request: %w", err)
	}

	return nil
}

// CreateImplicitInvitation enables invitee to create and send an exchange request using inviter public DID.
func (c *Client) CreateImplicitInvitation(inviterLabel, inviterDID string) (string, error) {
	return c.didexchangeSvc.CreateImplicitInvitation(inviterLabel, inviterDID, "", "")
}

// CreateImplicitInvitationWithDID enables invitee to create implicit invitation using inviter and invitee public DID.
func (c *Client) CreateImplicitInvitationWithDID(inviter, invitee *DIDInfo) (string, error) {
	if inviter == nil || invitee == nil {
		return "", errors.New("missing inviter and/or invitee public DID(s)")
	}

	return c.didexchangeSvc.CreateImplicitInvitation(inviter.Label, inviter.DID, invitee.Label, invitee.DID)
}

// QueryConnections queries connections matching given criteria(parameters)
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*Connection, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 - query all connections from all criteria and
	//  also results needs to be paged.
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
