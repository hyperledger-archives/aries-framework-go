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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = didexchange.InvitationMsgType
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = didexchange.RequestMsgType
	// ProtocolName is the framework's friendly name for the did exchange protocol
	ProtocolName = didexchange.DIDExchange
)

// ErrConnectionNotFound is returned when connection not found
var ErrConnectionNotFound = errors.New("connection not found")

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
}

// Client enable access to didexchange api
type Client struct {
	service.Event
	didexchangeSvc  protocolService
	routeSvc        mediator.ProtocolService
	legacyKMS       legacykms.KeyManager
	serviceEndpoint string
	connectionStore *connection.Recorder
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

	s, err := ctx.Service(mediator.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := s.(mediator.ProtocolService)
	if !ok {
		return nil, errors.New("cast service to Route Service failed")
	}

	connectionStore, err := connection.NewRecorder(ctx)
	if err != nil {
		return nil, err
	}

	return &Client{
		Event:           didexchangeSvc,
		didexchangeSvc:  didexchangeSvc,
		routeSvc:        routeSvc,
		legacyKMS:       ctx.LegacyKMS(),
		serviceEndpoint: ctx.ServiceEndpoint(),
		connectionStore: connectionStore,
	}, nil
}

// CreateInvitation creates an invitation. New key pair will be generated and base58 encoded public key will be
// used as basis for invitation. This invitation will be stored so client can cross reference this invitation during
// did exchange protocol
func (c *Client) CreateInvitation(label string) (*Invitation, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/623 'alias' should be passed as arg and persisted
	//  with connection record
	_, sigPubKey, err := c.legacyKMS.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed CreateSigningKey: %w", err)
	}

	// get the route configs
	serviceEndpoint, routingKeys, err := mediator.GetRouterConfig(c.routeSvc, c.serviceEndpoint)
	if err != nil {
		return nil, fmt.Errorf("create invitation - fetch router config : %w", err)
	}

	invitation := &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
		RecipientKeys:   []string{sigPubKey},
		ServiceEndpoint: serviceEndpoint,
		Type:            didexchange.InvitationMsgType,
		RoutingKeys:     routingKeys,
	}

	if err = mediator.AddKeyToRouter(c.routeSvc, sigPubKey); err != nil {
		return nil, fmt.Errorf("create invitation - add key to the router : %w", err)
	}

	err = c.connectionStore.SaveInvitation(invitation.ID, invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	return &Invitation{invitation}, nil
}

// CreateInvitationWithDID creates an invitation with specified public DID. This invitation will be stored
// so client can cross reference this invitation during did exchange protocol
func (c *Client) CreateInvitationWithDID(label, did string) (*Invitation, error) {
	invitation := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Label: label,
		DID:   did,
		Type:  didexchange.InvitationMsgType,
	}

	err := c.connectionStore.SaveInvitation(invitation.ID, invitation)
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

	msg, err := service.ParseDIDCommMsgMap(payload)
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

		if request.MyDID != "" && request.MyDID != record.MyDID {
			continue
		}

		if request.TheirDID != "" && request.TheirDID != record.TheirDID {
			continue
		}

		result = append(result, &Connection{Record: record})
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
func (c *Client) RemoveConnection(connectionID string) error {
	err := c.connectionStore.RemoveConnection(connectionID)
	if err != nil {
		return fmt.Errorf("cannot remove connection from the store: err=%w", err)
	}

	return nil
}
