/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockdidresolver "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didresolver"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// MockDIDExchangeSvc mock did exchange service
type MockDIDExchangeSvc struct {
	ProtocolName             string
	HandleFunc               func(*service.DIDCommMsg) error
	AcceptFunc               func(string) bool
	RegisterActionEventErr   error
	UnregisterActionEventErr error
	RegisterMsgEventErr      error
	UnregisterMsgEventErr    error
}

// HandleInbound msg
func (m *MockDIDExchangeSvc) HandleInbound(msg *service.DIDCommMsg) error {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
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

// MockProvider is provider for DIDExchange Service
type MockProvider struct {
	StoreProvider *mockstore.MockStoreProvider
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

// Signer is mock signer for DID exchange service
func (p *MockProvider) Signer() wallet.Signer {
	return &mockwallet.CloseableWallet{}
}

// DIDResolver is mock DID resolver
func (p *MockProvider) DIDResolver() didresolver.Resolver {
	return &mockdidresolver.MockResolver{}
}
