/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider mocks provider needed for did exchange service initialization.
type Provider struct {
	ServiceValue                      interface{}
	ServiceErr                        error
	ServiceMap                        map[string]interface{}
	KMSValue                          kms.KeyManager
	ServiceEndpointValue              string
	StorageProviderValue              storage.Provider
	ProtocolStateStorageProviderValue storage.Provider
	DIDConnectionStoreValue           did.ConnectionStore
	PackerList                        []packer.Packer
	PackerValue                       packer.Packer
	OutboundDispatcherValue           dispatcher.Outbound
	VDRegistryValue                   vdrapi.Registry
	CryptoValue                       crypto.Crypto
	JSONLDDocumentLoaderValue         ld.DocumentLoader
}

// Service return service.
func (p *Provider) Service(id string) (interface{}, error) {
	if p.ServiceErr != nil {
		return nil, p.ServiceErr
	}

	if p.ServiceMap[id] != nil {
		return p.ServiceMap[id], nil
	}

	return p.ServiceValue, nil
}

// KMS returns a kms instance.
func (p *Provider) KMS() kms.KeyManager {
	return p.KMSValue
}

// Crypto returns a crypto.
func (p *Provider) Crypto() crypto.Crypto {
	return p.CryptoValue
}

// ServiceEndpoint returns the service endpoint.
func (p *Provider) ServiceEndpoint() string {
	return p.ServiceEndpointValue
}

// RouterEndpoint returns the router transport endpoint.
func (p *Provider) RouterEndpoint() string {
	return p.ServiceEndpointValue
}

// StorageProvider returns the storage provider.
func (p *Provider) StorageProvider() storage.Provider {
	return p.StorageProviderValue
}

// ProtocolStateStorageProvider returns the protocol state storage provider.
func (p *Provider) ProtocolStateStorageProvider() storage.Provider {
	return p.ProtocolStateStorageProviderValue
}

// DIDConnectionStore returns the DID connection store.
func (p *Provider) DIDConnectionStore() did.ConnectionStore {
	return p.DIDConnectionStoreValue
}

// Packers returns the available Packer services.
func (p *Provider) Packers() []packer.Packer {
	return p.PackerList
}

// PrimaryPacker returns the main Packer service.
func (p *Provider) PrimaryPacker() packer.Packer {
	return p.PackerValue
}

// OutboundDispatcher return outbound dispatcher.
func (p *Provider) OutboundDispatcher() dispatcher.Outbound {
	return p.OutboundDispatcherValue
}

// VDRegistry return vdr registry.
func (p *Provider) VDRegistry() vdrapi.Registry {
	return p.VDRegistryValue
}

// JSONLDDocumentLoader returns JSON-LD document loader.
func (p *Provider) JSONLDDocumentLoader() ld.DocumentLoader {
	return p.JSONLDDocumentLoaderValue
}
