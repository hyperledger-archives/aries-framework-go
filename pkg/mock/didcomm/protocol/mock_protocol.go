/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockservice "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/service"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mocksecretlock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MockProvider is provider for DIDExchange Service.
type MockProvider struct {
	StoreProvider              storage.Provider
	ProtocolStateStoreProvider storage.Provider
	CustomVDR                  vdrapi.Registry
	CustomOutbound             *mockdispatcher.MockOutbound
	CustomMessenger            *mockservice.MockMessenger
	CustomKMS                  kms.KeyManager
	CustomLock                 secretlock.Service
	CustomCrypto               *mockcrypto.Crypto
	ServiceErr                 error
	ServiceMap                 map[string]interface{}
	InboundMsgHandler          transport.InboundMessageHandler
	OutboundMsgHandler         service.OutboundHandler
}

// OutboundDispatcher is mock outbound dispatcher for DID exchange service.
func (p *MockProvider) OutboundDispatcher() dispatcher.Outbound {
	if p.CustomOutbound != nil {
		return p.CustomOutbound
	}

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

// Crypto is mock crypto (including Signer) for DID exchange service.
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

// KMS returns mock kms instance.
func (p *MockProvider) KMS() kms.KeyManager {
	if p.CustomKMS != nil {
		return p.CustomKMS
	}

	return &mockkms.KeyManager{}
}

// SecretLock returns SecretLock instance.
func (p *MockProvider) SecretLock() secretlock.Service {
	if p.CustomLock != nil {
		return p.CustomLock
	}

	return &mocksecretlock.MockSecretLock{}
}

// Service return service.
func (p *MockProvider) Service(id string) (interface{}, error) {
	if p.ServiceErr != nil {
		return nil, p.ServiceErr
	}

	return p.ServiceMap[id], nil
}

// Messenger return mock messenger.
func (p *MockProvider) Messenger() service.Messenger {
	if p.CustomMessenger != nil {
		return p.CustomMessenger
	}

	return &mockservice.MockMessenger{}
}

// InboundMessageHandler handles an unpacked inbound message.
func (p *MockProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return p.InboundMsgHandler
}

// OutboundMessageHandler handles an outbound message.
func (p *MockProvider) OutboundMessageHandler() service.OutboundHandler {
	return p.OutboundMsgHandler
}
