/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockdidresolver "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didresolver"
	mockdidstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didstore"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockDIDExchangeSvc mock did exchange service
type MockDIDExchangeSvc struct {
	ProtocolName             string
	HandleFunc               func(*service.DIDCommMsg) (string, error)
	AcceptFunc               func(string) bool
	RegisterActionEventErr   error
	UnregisterActionEventErr error
	RegisterMsgEventErr      error
	UnregisterMsgEventErr    error
}

// HandleInbound msg
func (m *MockDIDExchangeSvc) HandleInbound(msg *service.DIDCommMsg) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
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
func (m *MockDIDExchangeSvc) AcceptExchangeRequest(connectionID string) error {
	return nil
}

// MockProvider is provider for DIDExchange Service
type MockProvider struct {
	StoreProvider          *mockstore.MockStoreProvider
	TransientStoreProvider *mockstore.MockStoreProvider
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
func (p *MockProvider) Signer() kms.Signer {
	return &mockkms.CloseableKMS{}
}

// DIDResolver is mock DID resolver
func (p *MockProvider) DIDResolver() didresolver.Resolver {
	return &mockdidresolver.MockResolver{}
}

// DIDStore is mock DID store
func (p *MockProvider) DIDStore() didstore.Storage {
	return mockdidstore.NewMockDidStore()
}
