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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockDIDExchangeSvc mock did exchange service
type MockDIDExchangeSvc struct {
	ProtocolName             string
	HandleFunc               func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc       func(msg service.DIDCommMsg, myDID, theirDID string) error
	AcceptFunc               func(string) bool
	RegisterActionEventErr   error
	UnregisterActionEventErr error
	RegisterMsgEventErr      error
	UnregisterMsgEventErr    error
	AcceptError              error
	ImplicitInvitationErr    error
	RespondToFunc            func(*didexchange.OOBInvitation) (string, error)
	SaveFunc                 func(invitation *didexchange.OOBInvitation) error
}

// HandleInbound msg
func (m *MockDIDExchangeSvc) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg
func (m *MockDIDExchangeSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return nil
}

// Accept msg checks the msg type
func (m *MockDIDExchangeSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name
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

	return nil
}

// UnregisterMsgEvent unregister message event.
func (m *MockDIDExchangeSvc) UnregisterMsgEvent(ch chan<- service.StateMsg) error {
	if m.UnregisterMsgEventErr != nil {
		return m.UnregisterMsgEventErr
	}

	return nil
}

// AcceptExchangeRequest accepts/approves exchange request.
func (m *MockDIDExchangeSvc) AcceptExchangeRequest(connectionID, publicDID, label string) error {
	if m.AcceptError != nil {
		return m.AcceptError
	}

	return nil
}

// AcceptInvitation accepts/approves exchange invitation.
func (m *MockDIDExchangeSvc) AcceptInvitation(connectionID, publicDID, label string) error {
	if m.AcceptError != nil {
		return m.AcceptError
	}

	return nil
}

// CreateImplicitInvitation creates implicit invitation using public DID(s)
func (m *MockDIDExchangeSvc) CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel, inviteeDID string) (string, error) { //nolint: lll
	if m.ImplicitInvitationErr != nil {
		return "", m.ImplicitInvitationErr
	}

	return "connection-id", nil
}

// RespondTo this invitation.
func (m *MockDIDExchangeSvc) RespondTo(i *didexchange.OOBInvitation) (string, error) {
	if m.RespondToFunc != nil {
		return m.RespondToFunc(i)
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

// MockProvider is provider for DIDExchange Service
type MockProvider struct {
	StoreProvider          *mockstore.MockStoreProvider
	TransientStoreProvider *mockstore.MockStoreProvider
	CustomVDRI             vdriapi.Registry
}

// OutboundDispatcher is mock outbound dispatcher for DID exchange service
func (p *MockProvider) OutboundDispatcher() dispatcher.Outbound {
	return &mockdispatcher.MockOutbound{}
}

// StorageProvider is mock storage provider for DID exchange service
func (p *MockProvider) StorageProvider() storage.Provider {
	if p.StoreProvider != nil {
		return p.StoreProvider
	}

	return mockstore.NewMockStoreProvider()
}

// TransientStorageProvider is mock transient storage provider for DID exchange service
func (p *MockProvider) TransientStorageProvider() storage.Provider {
	if p.TransientStoreProvider != nil {
		return p.TransientStoreProvider
	}

	return mockstore.NewMockStoreProvider()
}

// Signer is mock signer for DID exchange service
func (p *MockProvider) Signer() legacykms.Signer {
	return &mockkms.CloseableKMS{}
}

// VDRIRegistry is mock vdri registry
func (p *MockProvider) VDRIRegistry() vdriapi.Registry {
	if p.CustomVDRI != nil {
		return p.CustomVDRI
	}

	return &mockvdri.MockVDRIRegistry{}
}
