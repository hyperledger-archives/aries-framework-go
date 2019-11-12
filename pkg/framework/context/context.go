/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundDispatcher       dispatcher.Outbound
	services                 []dispatcher.Service
	storeProvider            storage.Provider
	transientStoreProvider   storage.Provider
	kms                      kms.KMS
	packager                 commontransport.Packager
	primaryPacker            packer.Packer
	packers                  []packer.Packer
	inboundTransportEndpoint string
	outboundTransport        transport.OutboundTransport
	didResolver              didresolver.Resolver
	didCreator               didcreator.Creator
	didStore                 didstore.Storage
}

// New instantiates a new context provider.
func New(opts ...ProviderOption) (*Provider, error) {
	ctxProvider := Provider{}

	for _, opt := range opts {
		err := opt(&ctxProvider)
		if err != nil {
			return nil, fmt.Errorf("option failed: %w", err)
		}
	}

	return &ctxProvider, nil
}

// OutboundDispatcher returns an outbound dispatcher.
func (p *Provider) OutboundDispatcher() dispatcher.Outbound {
	return p.outboundDispatcher
}

// OutboundTransports returns an outbound transports.
func (p *Provider) OutboundTransports() []transport.OutboundTransport {
	return []transport.OutboundTransport{p.outboundTransport}
}

// Service return protocol service
func (p *Provider) Service(id string) (interface{}, error) {
	for _, v := range p.services {
		if v.Name() == id {
			return v, nil
		}
	}

	return nil, api.ErrSvcNotFound
}

// KMS returns a kms service.
func (p *Provider) KMS() kms.KeyManager {
	return p.kms
}

// Packager returns a packager service.
func (p *Provider) Packager() commontransport.Packager {
	return p.packager
}

// Packers returns a list of enabled packers.
func (p *Provider) Packers() []packer.Packer {
	return p.packers
}

// PrimaryPacker returns the main inbound/outbound Packer service.
func (p *Provider) PrimaryPacker() packer.Packer {
	return p.primaryPacker
}

// Signer returns a kms signing service.
func (p *Provider) Signer() kms.Signer {
	return p.kms
}

// InboundTransportEndpoint returns an inbound transport endpoint.
func (p *Provider) InboundTransportEndpoint() string {
	return p.inboundTransportEndpoint
}

// InboundMessageHandler return an inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte) error {
		msg, err := service.NewDIDCommMsg(message)
		if err != nil {
			return err
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msg.Header.Type) {
				_, err = svc.HandleInbound(msg)
				return err
			}
		}
		return fmt.Errorf("no message handlers found for the message type: %s", msg.Header.Type)
	}
}

// StorageProvider return a storage provider.
func (p *Provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

// TransientStorageProvider return a transient storage provider.
func (p *Provider) TransientStorageProvider() storage.Provider {
	return p.transientStoreProvider
}

// DIDResolver returns a DID resolver.
func (p *Provider) DIDResolver() didresolver.Resolver {
	return p.didResolver
}

// DIDCreator returns a DID creator.
func (p *Provider) DIDCreator() didcreator.Creator {
	return p.didCreator
}

// DIDStore returns a DID store.
func (p *Provider) DIDStore() didstore.Storage {
	return p.didStore
}

// ProviderOption configures the framework.
type ProviderOption func(opts *Provider) error

// WithOutboundDispatcher injects an outbound dispatcher into the context.
func WithOutboundDispatcher(ot dispatcher.Outbound) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundDispatcher = ot
		return nil
	}
}

// WithOutboundTransport injects an outbound transport into the context.
func WithOutboundTransport(ot transport.OutboundTransport) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundTransport = ot
		return nil
	}
}

// WithProtocolServices injects a protocol services into the context.
func WithProtocolServices(services ...dispatcher.Service) ProviderOption {
	return func(opts *Provider) error {
		opts.services = services
		return nil
	}
}

// WithDIDStore injects a DID store into the context.
func WithDIDStore(store didstore.Storage) ProviderOption {
	return func(opts *Provider) error {
		opts.didStore = store
		return nil
	}
}

// WithKMS injects a kms service into the context.
func WithKMS(w kms.KMS) ProviderOption {
	return func(opts *Provider) error {
		opts.kms = w
		return nil
	}
}

// WithInboundTransportEndpoint injects an inbound transport endpoint into the context.
func WithInboundTransportEndpoint(endpoint string) ProviderOption {
	return func(opts *Provider) error {
		opts.inboundTransportEndpoint = endpoint
		return nil
	}
}

// WithStorageProvider injects a storage provider into the context.
func WithStorageProvider(s storage.Provider) ProviderOption {
	return func(opts *Provider) error {
		opts.storeProvider = s
		return nil
	}
}

// WithTransientStorageProvider injects a transient storage provider into the context.
func WithTransientStorageProvider(s storage.Provider) ProviderOption {
	return func(opts *Provider) error {
		opts.transientStoreProvider = s
		return nil
	}
}

// WithDIDResolver injects DID resolver into the context.
func WithDIDResolver(r didresolver.Resolver) ProviderOption {
	return func(opts *Provider) error {
		opts.didResolver = r
		return nil
	}
}

// WithPackager injects a packager into the context.
func WithPackager(p commontransport.Packager) ProviderOption {
	return func(opts *Provider) error {
		opts.packager = p
		return nil
	}
}

// WithPacker injects at least one Packer into the context,
// with the primary Packer being used for inbound/outbound communication
// and the additional packers being available for unpacking inbound messages.
func WithPacker(primary packer.Packer, additionalPackers ...packer.Packer) ProviderOption {
	return func(opts *Provider) error {
		opts.primaryPacker = primary
		opts.packers = append(opts.packers, additionalPackers...)
		return nil
	}
}
