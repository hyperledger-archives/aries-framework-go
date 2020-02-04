/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockProvider is provider for DIDExchange Service
type MockProvider struct {
	StoreProvider          *mockstore.MockStoreProvider
	TransientStoreProvider *mockstore.MockStoreProvider
	CustomVDRI             vdriapi.Registry
	CustomOutbound         *mockdispatcher.MockOutbound
	CustomKMS              *mockkms.CloseableKMS
	ServiceErr             error
	ServiceMap             map[string]interface{}
}

// OutboundDispatcher is mock outbound dispatcher for DID exchange service
func (p *MockProvider) OutboundDispatcher() dispatcher.Outbound {
	if p.CustomOutbound != nil {
		return p.CustomOutbound
	}

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

// LegacyKMS returns mock LegacyKMS
func (p *MockProvider) LegacyKMS() legacykms.KeyManager {
	if p.CustomKMS != nil {
		return p.CustomKMS
	}

	return &mockkms.CloseableKMS{}
}

// Service return service
func (p *MockProvider) Service(id string) (interface{}, error) {
	if p.ServiceErr != nil {
		return nil, p.ServiceErr
	}

	return p.ServiceMap[id], nil
}
