/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider mocks provider needed for did exchange service initialization
type Provider struct {
	ServiceValue                  interface{}
	ServiceErr                    error
	ServiceMap                    map[string]interface{}
	KMSValue                      legacykms.KeyManager
	LegacyKMSValue                legacykms.KMS
	ServiceEndpointValue          string
	StorageProviderValue          storage.Provider
	TransientStorageProviderValue storage.Provider
	PackerList                    []packer.Packer
	PackerValue                   packer.Packer
	OutboundDispatcherValue       dispatcher.Outbound
	VDRIRegistryValue             vdriapi.Registry
}

// Service return service
func (p *Provider) Service(id string) (interface{}, error) {
	if p.ServiceErr != nil {
		return nil, p.ServiceErr
	}

	if p.ServiceMap[id] != nil {
		return p.ServiceMap[id], nil
	}

	return p.ServiceValue, nil
}

// LegacyKMS returns a LegacyKMS instance
func (p *Provider) LegacyKMS() legacykms.KeyManager {
	return p.KMSValue
}

// ServiceEndpoint returns the service endpoint
func (p *Provider) ServiceEndpoint() string {
	return p.ServiceEndpointValue
}

// RouterEndpoint returns the router transport endpoint
func (p *Provider) RouterEndpoint() string {
	return p.ServiceEndpointValue
}

// StorageProvider returns the storage provider
func (p *Provider) StorageProvider() storage.Provider {
	return p.StorageProviderValue
}

// TransientStorageProvider returns the transient storage provider
func (p *Provider) TransientStorageProvider() storage.Provider {
	return p.TransientStorageProviderValue
}

// Packers returns the available Packer services
func (p *Provider) Packers() []packer.Packer {
	return p.PackerList
}

// PrimaryPacker returns the main Packer service
func (p *Provider) PrimaryPacker() packer.Packer {
	return p.PackerValue
}

// OutboundDispatcher return outbound dispatcher
func (p *Provider) OutboundDispatcher() dispatcher.Outbound {
	return p.OutboundDispatcherValue
}

// VDRIRegistry return vdri registry
func (p *Provider) VDRIRegistry() vdriapi.Registry {
	return p.VDRIRegistryValue
}

// Signer returns a legacyKMS signing service.
func (p *Provider) Signer() legacykms.Signer {
	return p.LegacyKMSValue
}
