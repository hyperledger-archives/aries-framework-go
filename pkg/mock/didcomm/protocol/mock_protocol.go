/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockservice "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/service"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockProvider is provider for DIDExchange Service.
type MockProvider struct {
	StoreProvider              *mockstore.MockStoreProvider
	ProtocolStateStoreProvider *mockstore.MockStoreProvider
	CustomVDRI                 vdriapi.Registry
	CustomOutbound             *mockdispatcher.MockOutbound
	CustomMessenger            *mockservice.MockMessenger
	CustomKMS                  *mockkms.CloseableKMS
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

// Signer is mock signer for DID exchange service.
func (p *MockProvider) Signer() legacykms.Signer {
	return &mockkms.CloseableKMS{}
}

// VDRIRegistry is mock vdri registry.
func (p *MockProvider) VDRIRegistry() vdriapi.Registry {
	if p.CustomVDRI != nil {
		return p.CustomVDRI
	}

	return &mockvdri.MockVDRIRegistry{}
}

// LegacyKMS returns mock LegacyKMS.
func (p *MockProvider) LegacyKMS() legacykms.KeyManager {
	if p.CustomKMS != nil {
		return p.CustomKMS
	}

	return &mockkms.CloseableKMS{}
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
