/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	mockStorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// Provider mocks provider needed for did exchange service initialization
type Provider struct {
	ServiceValue         interface{}
	ServiceErr           error
	WalletValue          wallet.Crypto
	InboundEndpointValue string
}

// Service return service
func (p *Provider) Service(id string) (interface{}, error) {
	return p.ServiceValue, p.ServiceErr
}

// CryptoWallet return crypto wallet
func (p *Provider) CryptoWallet() wallet.Crypto {
	return p.WalletValue
}

// InboundTransportEndpoint returns the inbound transport endpoint
func (p *Provider) InboundTransportEndpoint() string {
	return p.InboundEndpointValue
}

// StorageProvider returns the storage provider
func (p *Provider) StorageProvider() storage.Provider {
	return mockStorage.NewMockStoreProvider()
}
