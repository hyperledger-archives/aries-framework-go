/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"time"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
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
	ContextStoreValue                 ld.ContextStore
	RemoteProviderStoreValue          ld.RemoteProviderStore
	DocumentLoaderValue               jsonld.DocumentLoader
	KeyTypeValue                      kms.KeyType
	KeyAgreementTypeValue             kms.KeyType
	MediaTypeProfilesValue            []string
	InboundMessageHandlerValue        transport.InboundMessageHandler
	PackagerValue                     transport.Packager
	MessageServiceProviderValue       api.MessageServiceProvider
	InboundMessengerValue             service.InboundMessenger
	GetDIDsBackoffDurationValue       time.Duration
	GetDIDsMaxRetriesValue            uint64
	DIDRotatorValue                   didrotate.DIDRotator
	MessengerValue                    service.Messenger
}

// Messenger return messenger.
func (p *Provider) Messenger() service.Messenger {
	return p.MessengerValue
}

// MessageServiceProvider return message service provider.
func (p *Provider) MessageServiceProvider() api.MessageServiceProvider {
	return p.MessageServiceProviderValue
}

// AllServices return all services.
func (p *Provider) AllServices() []dispatcher.ProtocolService {
	out := []dispatcher.ProtocolService{}

	for _, v := range p.ServiceMap {
		out = append(out, v.(dispatcher.ProtocolService))
	}

	if p.ServiceValue != nil {
		out = append(out, p.ServiceValue.(dispatcher.ProtocolService))
	}

	return out
}

// GetDIDsBackOffDuration return backoff duration for getting DIDs.
func (p *Provider) GetDIDsBackOffDuration() time.Duration {
	return p.GetDIDsBackoffDurationValue
}

// GetDIDsMaxRetries return max number of retries for getting DIDs.
func (p *Provider) GetDIDsMaxRetries() uint64 {
	return p.GetDIDsMaxRetriesValue
}

// InboundMessenger return inbound messenger.
func (p *Provider) InboundMessenger() service.InboundMessenger {
	return p.InboundMessengerValue
}

// InboundMessageHandler return inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return p.InboundMessageHandlerValue
}

// Packager return packager.
func (p *Provider) Packager() transport.Packager {
	return p.PackagerValue
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

// JSONLDContextStore returns JSON-LD context store.
func (p *Provider) JSONLDContextStore() ld.ContextStore {
	return p.ContextStoreValue
}

// JSONLDRemoteProviderStore returns remote JSON-LD context provider store.
func (p *Provider) JSONLDRemoteProviderStore() ld.RemoteProviderStore {
	return p.RemoteProviderStoreValue
}

// MediaTypeProfiles returns the media type profiles.
func (p *Provider) MediaTypeProfiles() []string {
	return p.MediaTypeProfilesValue
}

// JSONLDDocumentLoader returns JSON-LD document loader.
func (p *Provider) JSONLDDocumentLoader() jsonld.DocumentLoader {
	return p.DocumentLoaderValue
}

// KeyType returns a mocked keyType value for authentication (signing).
func (p *Provider) KeyType() kms.KeyType {
	return p.KeyTypeValue
}

// KeyAgreementType returns a mocked keyType value for KeyAgreement.
func (p *Provider) KeyAgreementType() kms.KeyType {
	return p.KeyAgreementTypeValue
}

// DIDRotator returns the did rotator.
func (p *Provider) DIDRotator() *didrotate.DIDRotator {
	return &p.DIDRotatorValue
}
