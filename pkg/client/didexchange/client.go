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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = didexchange.InvitationMsgType
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = didexchange.RequestMsgType
	// ProtocolName is the framework's friendly name for the did exchange protocol.
	ProtocolName = didexchange.DIDExchange
)

// ErrConnectionNotFound is returned when connection not found.
var ErrConnectionNotFound = errors.New("connection not found")

type options struct {
	routerConnections  []string
	routerConnectionID string
	keyType            kms.KeyType
}

func applyOptions(args ...Opt) *options {
	opts := &options{}

	for i := range args {
		args[i](opts)
	}

	return opts
}

// Opt represents option function.
type Opt func(*options)

// InvOpt represents option for the CreateInvitation function.
type InvOpt Opt

// WithRouterConnectionID allows you to specify the router connection ID.
func WithRouterConnectionID(conn string) InvOpt {
	return func(opts *options) {
		opts.routerConnectionID = conn
	}
}

// WithRouterConnections allows you to specify the router connections.
func WithRouterConnections(conns ...string) Opt {
	return func(opts *options) {
		for _, conn := range conns {
			// filters out empty connections
			if conn != "" {
				opts.routerConnections = append(opts.routerConnections, conn)
			}
		}
	}
}

// WithKeyType sets the key type to use in the didexchange invitation. DIDcomm v1 requires ED25519 key type, while
// DIDComm V2 requires either NISTP(256/384/521)ECDHKW key type or X25519ECDHKW key type.
func WithKeyType(keyType kms.KeyType) InvOpt {
	return func(opts *options) {
		opts.keyType = keyType
	}
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context().
type provider interface {
	Service(id string) (interface{}, error)
	KMS() kms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// Client enable access to didexchange api.
type Client struct {
	service.Event
	didexchangeSvc    protocolService
	routeSvc          mediator.ProtocolService
	kms               kms.KeyManager
	serviceEndpoint   string
	connectionStore   *connection.Recorder
	keyType           kms.KeyType
	keyAgreementType  kms.KeyType
	mediaTypeProfiles []string
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.DIDComm

	// Accepts/Approves exchange request
	AcceptExchangeRequest(connectionID, publicDID, label string, routerConnections []string) error

	// Accepts/Approves exchange invitation
	AcceptInvitation(connectionID, publicDID, label string, routerConnections []string) error

	// CreateImplicitInvitation creates implicit invitation. Inviter DID is required, invitee DID is optional.
	// If invitee DID is not provided new peer DID will be created for implicit invitation exchange request.
	CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel,
		inviteeDID string, routerConnections []string) (string, error)

	// CreateConnection saves the connection record.
	CreateConnection(*connection.Record, *did.Doc) error
}

// New return new instance of didexchange client.
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

	keyType := ctx.KeyType()
	if keyType == "" {
		keyType = kms.ED25519Type
	}

	keyAgreementType := ctx.KeyAgreementType()
	if keyAgreementType == "" {
		keyAgreementType = kms.X25519ECDHKWType
	}

	mtp := ctx.MediaTypeProfiles()
	if len(mtp) == 0 {
		mtp = []string{transport.MediaTypeRFC0019EncryptedEnvelope}
	}

	return &Client{
		Event:             didexchangeSvc,
		didexchangeSvc:    didexchangeSvc,
		routeSvc:          routeSvc,
		kms:               ctx.KMS(),
		serviceEndpoint:   ctx.ServiceEndpoint(),
		connectionStore:   connectionStore,
		keyType:           keyType,
		keyAgreementType:  keyAgreementType,
		mediaTypeProfiles: mtp,
	}, nil
}

// CreateInvitation creates an invitation. New key pair will be generated and did:key encoded public key will be
// used as basis for invitation. This invitation will be stored so client can cross-reference this invitation during
// did exchange protocol.
//nolint:funlen,gocyclo
func (c *Client) CreateInvitation(label string, args ...InvOpt) (*Invitation, error) {
	opts := &options{}

	for i := range args {
		args[i](opts)
	}

	keyType := c.keyType

	if opts.keyType != "" {
		keyType = opts.keyType
	} else {
		for _, mediaType := range c.mediaTypeProfiles {
			if mediaType == transport.MediaTypeDIDCommV2Profile || mediaType == transport.MediaTypeAIP2RFC0587Profile {
				keyType = c.keyAgreementType

				break
			}
		}
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/623 'alias' should be passed as arg and persisted
	//  with connection record
	_, pubKey, err := c.kms.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, fmt.Errorf("createInvitation: failed to extract public SigningKey bytes from handle: %w", err)
	}

	var didKey string

	switch keyType {
	case kms.ED25519Type:
		didKey, _ = fingerprint.CreateDIDKey(pubKey)
	default:
		didKey, err = kmsdidkey.BuildDIDKeyByKeyType(pubKey, keyType)
		if err != nil {
			return nil, fmt.Errorf("createInvitation: failed to build did:key by key type: %w", err)
		}
	}

	var (
		serviceEndpoint = c.serviceEndpoint
		routingKeys     []string
	)

	if opts.routerConnectionID != "" {
		// get the route configs
		serviceEndpoint, routingKeys, err = mediator.GetRouterConfig(c.routeSvc,
			opts.routerConnectionID, c.serviceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("createInvitation: getRouterConfig: %w", err)
		}

		if err = mediator.AddKeyToRouter(c.routeSvc, opts.routerConnectionID, didKey); err != nil {
			return nil, fmt.Errorf("createInvitation: AddKeyToRouter: %w", err)
		}
	}

	invitation := &didexchange.Invitation{
		ID:              uuid.New().String(),
		Label:           label,
		RecipientKeys:   []string{didKey},
		ServiceEndpoint: serviceEndpoint,
		Type:            didexchange.InvitationMsgType,
		RoutingKeys:     routingKeys,
	}

	err = c.connectionStore.SaveInvitation(invitation.ID, invitation)
	if err != nil {
		return nil, fmt.Errorf("createInvitation: failed to save invitation: %w", err)
	}

	return &Invitation{invitation}, nil
}

// CreateInvitationWithDID creates an invitation with specified public DID. This invitation will be stored
// so client can cross reference this invitation during did exchange protocol.
func (c *Client) CreateInvitationWithDID(label, publicDID string) (*Invitation, error) {
	invitation := &didexchange.Invitation{
		ID:    uuid.New().String(),
		Label: label,
		DID:   publicDID,
		Type:  didexchange.InvitationMsgType,
	}

	err := c.connectionStore.SaveInvitation(invitation.ID, invitation)
	if err != nil {
		return nil, fmt.Errorf("createInvitationWithDID: failed to save invitation with DID: %w", err)
	}

	return &Invitation{invitation}, nil
}

// HandleInvitation handle incoming invitation and returns the connectionID that can be used to query the state
// of did exchange protocol. Upon successful completion of did exchange protocol connection details will be used
// for securing communication between agents.
func (c *Client) HandleInvitation(invitation *Invitation) (string, error) {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return "", fmt.Errorf("handleInvitation: failed marshal invitation: %w", err)
	}

	msg, err := service.ParseDIDCommMsgMap(payload)
	if err != nil {
		return "", fmt.Errorf("handleInvitation: failed to create DIDCommMsg: %w", err)
	}

	connectionID, err := c.didexchangeSvc.HandleInbound(msg, service.EmptyDIDCommContext())
	if err != nil {
		return "", fmt.Errorf("handleInvitation: failed from didexchange service handle: %w", err)
	}

	return connectionID, nil
}

// TODO https://github.com/hyperledger/aries-framework-go/issues/754 - e.Continue v Explicit API call for action events

// AcceptInvitation accepts/approves exchange invitation. This call is not used if auto execute is setup
// for this client (see package example for more details about how to setup auto execute).
func (c *Client) AcceptInvitation(connectionID, publicDID, label string, args ...Opt) error {
	opts := applyOptions(args...)

	if err := c.didexchangeSvc.AcceptInvitation(connectionID, publicDID, label, opts.routerConnections); err != nil {
		return fmt.Errorf("did exchange client - accept exchange invitation: %w", err)
	}

	return nil
}

// AcceptExchangeRequest accepts/approves exchange request. This call is not used if auto execute is setup
// for this client (see package example for more details about how to setup auto execute).
func (c *Client) AcceptExchangeRequest(connectionID, publicDID, label string, args ...Opt) error {
	err := c.didexchangeSvc.AcceptExchangeRequest(connectionID, publicDID, label,
		applyOptions(args...).routerConnections)
	if err != nil {
		return fmt.Errorf("did exchange client - accept exchange request: %w", err)
	}

	return nil
}

// CreateImplicitInvitation enables invitee to create and send an exchange request using inviter public DID.
func (c *Client) CreateImplicitInvitation(inviterLabel, inviterDID string, args ...Opt) (string, error) {
	return c.didexchangeSvc.CreateImplicitInvitation(inviterLabel, inviterDID,
		"", "", applyOptions(args...).routerConnections)
}

// CreateImplicitInvitationWithDID enables invitee to create implicit invitation using inviter and invitee public DID.
func (c *Client) CreateImplicitInvitationWithDID(inviter, invitee *DIDInfo) (string, error) {
	if inviter == nil || invitee == nil {
		return "", errors.New("missing inviter and/or invitee public DID(s)")
	}

	return c.didexchangeSvc.CreateImplicitInvitation(inviter.Label, inviter.DID, invitee.Label, invitee.DID, nil)
}

// QueryConnections queries connections matching given criteria(parameters).
func (c *Client) QueryConnections(request *QueryConnectionsParams) ([]*Connection, error) { //nolint: gocyclo
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

		if request.InvitationID != "" && request.InvitationID != record.InvitationID {
			continue
		}

		if request.ParentThreadID != "" && request.ParentThreadID != record.ParentThreadID {
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

// GetConnection fetches single connection record for given id.
func (c *Client) GetConnection(connectionID string) (*Connection, error) {
	conn, err := c.connectionStore.GetConnectionRecord(connectionID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrConnectionNotFound
		}

		return nil, fmt.Errorf("cannot fetch state from store: connectionid=%s err=%w", connectionID, err)
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

		return nil, fmt.Errorf("cannot fetch state from store: connectionid=%s err=%w", connectionID, err)
	}

	return &Connection{
		conn,
	}, nil
}

// CreateConnection creates a new connection between myDID and theirDID and returns the connectionID.
func (c *Client) CreateConnection(myDID string, theirDID *did.Doc, options ...ConnectionOption) (string, error) {
	conn := &Connection{&connection.Record{
		ConnectionID: uuid.New().String(),
		State:        connection.StateNameCompleted,
		TheirDID:     theirDID.ID,
		MyDID:        myDID,
		Namespace:    connection.MyNSPrefix,
	}}

	for i := range options {
		options[i](conn)
	}

	destination, err := service.CreateDestination(theirDID)
	if err != nil {
		return "", fmt.Errorf("createConnection: failed to create destination: %w", err)
	}

	conn.ServiceEndPoint = destination.ServiceEndpoint
	conn.RecipientKeys = destination.RecipientKeys
	conn.RoutingKeys = destination.RoutingKeys

	err = c.didexchangeSvc.CreateConnection(conn.Record, theirDID)
	if err != nil {
		return "", fmt.Errorf("createConnection: err: %w", err)
	}

	return conn.ConnectionID, nil
}

// RemoveConnection removes connection record for given id.
func (c *Client) RemoveConnection(connectionID string) error {
	err := c.connectionStore.RemoveConnection(connectionID)
	if err != nil {
		return fmt.Errorf("cannot remove connection from the store: err=%w", err)
	}

	return nil
}

// ConnectionOption allows you to customize details of the connection record.
type ConnectionOption func(*Connection)

// WithTheirLabel sets TheirLabel on the connection record.
func WithTheirLabel(l string) ConnectionOption {
	return func(c *Connection) {
		c.TheirLabel = l
	}
}

// WithThreadID sets ThreadID on the connection record.
func WithThreadID(thid string) ConnectionOption {
	return func(c *Connection) {
		c.ThreadID = thid
	}
}

// WithParentThreadID sets ParentThreadID on the connection record.
func WithParentThreadID(pthid string) ConnectionOption {
	return func(c *Connection) {
		c.ParentThreadID = pthid
	}
}

// WithInvitationID sets InvitationID on the connection record.
func WithInvitationID(id string) ConnectionOption {
	return func(c *Connection) {
		c.InvitationID = id
	}
}

// WithInvitationDID sets InvitationDID on the connection record.
func WithInvitationDID(didID string) ConnectionOption {
	return func(c *Connection) {
		c.InvitationDID = didID
	}
}

// WithImplicit sets Implicit on the connection record.
func WithImplicit(i bool) ConnectionOption {
	return func(c *Connection) {
		c.Implicit = i
	}
}
