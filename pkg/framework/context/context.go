/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundDispatcher       dispatcher.Outbound
	services                 []dispatcher.Service
	storeProvider            storage.Provider
	wallet                   wallet.Wallet
	packager                 envelope.Packager
	crypter                  crypto.Crypter
	inboundTransportEndpoint string
	outboundTransport        transport.OutboundTransport
	didResolver              didresolver.Resolver
	didCreator               didcreator.Creator
	didStore                 didstore.Storage
}

// New instantiated new context provider
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

// OutboundDispatcher returns the outbound dispatcher
func (p *Provider) OutboundDispatcher() dispatcher.Outbound {
	return p.outboundDispatcher
}

// OutboundTransports returns the outbound transports
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

// CryptoWallet returns the crypto wallet service
func (p *Provider) CryptoWallet() wallet.Crypto {
	return p.wallet
}

// Packager returns the packager service
func (p *Provider) Packager() envelope.Packager {
	return p.packager
}

// Crypter returns the crypter service to be used by the packager
func (p *Provider) Crypter() crypto.Crypter {
	return p.crypter
}

// Signer returns the wallet signing service
func (p *Provider) Signer() wallet.Signer {
	return p.wallet
}

// InboundTransportEndpoint returns the inbound transport endpoint
func (p *Provider) InboundTransportEndpoint() string {
	return p.inboundTransportEndpoint
}

// InboundMessageHandler return inbound message handler
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte) error {
		msg, err := service.NewDIDCommMsg(message)
		if err != nil {
			return err
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msg.Header.Type) {
				return svc.HandleInbound(msg)
			}
		}
		return fmt.Errorf("no message handlers found for the message type: %s", msg.Header.Type)
	}
}

// StorageProvider return storage provider
func (p *Provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

// DIDResolver returns did resolver
func (p *Provider) DIDResolver() didresolver.Resolver {
	return p.didResolver
}

// DIDCreator returns did creator
func (p *Provider) DIDCreator() didcreator.Creator {
	return p.didCreator
}

// DIDStore returns did store
func (p *Provider) DIDStore() didstore.Storage {
	return p.didStore
}

// ProviderOption configures the framework.
type ProviderOption func(opts *Provider) error

// WithOutboundDispatcher injects outbound dispatcher into the context
func WithOutboundDispatcher(ot dispatcher.Outbound) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundDispatcher = ot
		return nil
	}
}

// WithOutboundTransport injects outbound transport into the context
func WithOutboundTransport(ot transport.OutboundTransport) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundTransport = ot
		return nil
	}
}

// WithProtocolServices injects protocol services into the context.
func WithProtocolServices(services ...dispatcher.Service) ProviderOption {
	return func(opts *Provider) error {
		opts.services = services
		return nil
	}
}

// WithDIDStore injects did store into the context.
func WithDIDStore(store didstore.Storage) ProviderOption {
	return func(opts *Provider) error {
		opts.didStore = store
		return nil
	}
}

// WithWallet injects a wallet service into the context
func WithWallet(w wallet.Wallet) ProviderOption {
	return func(opts *Provider) error {
		opts.wallet = w
		return nil
	}
}

// WithInboundTransportEndpoint injects a inbound transport endpoint into the context
func WithInboundTransportEndpoint(endpoint string) ProviderOption {
	return func(opts *Provider) error {
		opts.inboundTransportEndpoint = endpoint
		return nil
	}
}

// WithStorageProvider injects a storage provider into the context
func WithStorageProvider(s storage.Provider) ProviderOption {
	return func(opts *Provider) error {
		opts.storeProvider = s
		return nil
	}
}

// WithDIDResolver injects did resolver into the context
func WithDIDResolver(r didresolver.Resolver) ProviderOption {
	return func(opts *Provider) error {
		opts.didResolver = r
		return nil
	}
}

// WithPackager injects a packager into the context
func WithPackager(p envelope.Packager) ProviderOption {
	return func(opts *Provider) error {
		opts.packager = p
		return nil
	}
}

// WithCrypter injects a crypter into the context
func WithCrypter(p crypto.Crypter) ProviderOption {
	return func(opts *Provider) error {
		opts.crypter = p
		return nil
	}
}
