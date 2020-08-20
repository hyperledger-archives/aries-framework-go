/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
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
	PackerList                        []packer.Packer
	PackerValue                       packer.Packer
	OutboundDispatcherValue           dispatcher.Outbound
	VDRIRegistryValue                 vdriapi.Registry
	CryptoValue                       crypto.Crypto
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

// VDRIRegistry return vdri registry.
func (p *Provider) VDRIRegistry() vdriapi.Registry {
	return p.VDRIRegistryValue
}
