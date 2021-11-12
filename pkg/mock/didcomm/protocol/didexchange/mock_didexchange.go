/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package didexchange

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MockDIDExchangeSvc mock did exchange service.
type MockDIDExchangeSvc struct {
	ProtocolName             string
	HandleFunc               func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc       func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc               func(string) bool
	RegisterActionEventErr   error
	UnregisterActionEventErr error
	RegisterMsgEventHandle   func(chan<- service.StateMsg) error
	RegisterMsgEventErr      error
	UnregisterMsgEventHandle func(chan<- service.StateMsg) error
	UnregisterMsgEventErr    error
	AcceptError              error
	ImplicitInvitationErr    error
	RespondToFunc            func(*didexchange.OOBInvitation, []string) (string, error)
	SaveFunc                 func(invitation *didexchange.OOBInvitation) error
	CreateConnRecordFunc     func(*connection.Record, *did.Doc) error
}

// Initialize service.
func (m *MockDIDExchangeSvc) Initialize(interface{}) error {
	return nil
}

// HandleInbound msg.
func (m *MockDIDExchangeSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg.
func (m *MockDIDExchangeSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

// Accept msg checks the msg type.
func (m *MockDIDExchangeSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name.
func (m *MockDIDExchangeSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "didexchange"
}

// RegisterActionEvent register action event.
func (m *MockDIDExchangeSvc) RegisterActionEvent(ch chan<- service.DIDCommAction) error {
	if m.RegisterActionEventErr != nil {
		return m.RegisterActionEventErr
	}

	return nil
}

// UnregisterActionEvent unregister action event.
func (m *MockDIDExchangeSvc) UnregisterActionEvent(ch chan<- service.DIDCommAction) error {
	if m.UnregisterActionEventErr != nil {
		return m.UnregisterActionEventErr
	}

	return nil
}

// RegisterMsgEvent register message event.
func (m *MockDIDExchangeSvc) RegisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.RegisterMsgEventErr != nil {
		return m.RegisterMsgEventErr
	}

	if m.RegisterMsgEventHandle != nil {
		return m.RegisterMsgEventHandle(ch)
	}

	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockDIDExchangeSvc) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.UnregisterMsgEventErr != nil {
		return m.UnregisterMsgEventErr
	}

	if m.UnregisterMsgEventHandle != nil {
		return m.UnregisterMsgEventHandle(ch)
	}

	return nil
}

// AcceptExchangeRequest accepts/approves exchange request.
func (m *MockDIDExchangeSvc) AcceptExchangeRequest(connectionID, publicDID, label string, conns []string) error {
	if m.AcceptError != nil {
		return m.AcceptError
	}

	return nil
}

// AcceptInvitation accepts/approves exchange invitation.
func (m *MockDIDExchangeSvc) AcceptInvitation(connectionID, publicDID, label string, conns []string) error {
	if m.AcceptError != nil {
		return m.AcceptError
	}

	return nil
}

// CreateImplicitInvitation creates implicit invitation using public DID(s).
func (m *MockDIDExchangeSvc) CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel, inviteeDID string, conns []string) (string, error) { //nolint: lll
	if m.ImplicitInvitationErr != nil {
		return "", m.ImplicitInvitationErr
	}

	return "connection-id", nil
}

// RespondTo this invitation.
func (m *MockDIDExchangeSvc) RespondTo(i *didexchange.OOBInvitation, conns []string) (string, error) {
	if m.RespondToFunc != nil {
		return m.RespondToFunc(i, conns)
	}

	return "", nil
}

// SaveInvitation this invitation.
func (m *MockDIDExchangeSvc) SaveInvitation(i *didexchange.OOBInvitation) error {
	if m.SaveFunc != nil {
		return m.SaveFunc(i)
	}

	return nil
}

// CreateConnection saves the connection record.
func (m *MockDIDExchangeSvc) CreateConnection(r *connection.Record, theirDID *did.Doc) error {
	if m.CreateConnRecordFunc != nil {
		return m.CreateConnRecordFunc(r, theirDID)
	}

	return nil
}

// MockProvider is provider for DIDExchange Service.
type MockProvider struct {
	StoreProvider              *mockstore.MockStoreProvider
	ProtocolStateStoreProvider *mockstore.MockStoreProvider
	CustomVDR                  vdrapi.Registry
}

// OutboundDispatcher is mock outbound dispatcher for DID exchange service.
func (p *MockProvider) OutboundDispatcher() dispatcher.Outbound {
	return &mockdispatcher.MockOutbound{}
}

// StorageProvider is mock storage provider for DID exchange service.
func (p *MockProvider) StorageProvider() storage.Provider {
	if p.StoreProvider != nil {
		return p.StoreProvider
	}

	return mockstore.NewMockStoreProvider()
}

// ProtocolStateStorageProvider is mock protocol state storage provider for DID exchange service.
func (p *MockProvider) ProtocolStateStorageProvider() storage.Provider {
	if p.ProtocolStateStoreProvider != nil {
		return p.ProtocolStateStoreProvider
	}

	return mockstore.NewMockStoreProvider()
}

// Crypto is mock crypto service for DID exchange service.
func (p *MockProvider) Crypto() crypto.Crypto {
	return &mockcrypto.Crypto{}
}

// VDRegistry is mock vdr registry.
func (p *MockProvider) VDRegistry() vdrapi.Registry {
	if p.CustomVDR != nil {
		return p.CustomVDR
	}

	return &mockvdr.MockVDRegistry{}
}

// MockEventProperties is a didexchange.Event.
type MockEventProperties struct {
	ConnID     string
	InvID      string
	Properties map[string]interface{}
}

// ConnectionID returns the connection id.
func (m *MockEventProperties) ConnectionID() string {
	return m.ConnID
}

// InvitationID returns the invitation id.
func (m *MockEventProperties) InvitationID() string {
	return m.InvID
}

// All returns all properties.
func (m *MockEventProperties) All() map[string]interface{} {
	p := map[string]interface{}{
		"connectionID": m.ConnectionID(),
		"invitationID": m.InvitationID(),
	}

	for k, v := range m.Properties {
		p[k] = v
	}

	return p
}
