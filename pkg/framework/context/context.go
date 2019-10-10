/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundDispatcher       dispatcher.Outbound
	services                 []dispatcher.Service
	storeProvider            storage.Provider
	wallet                   wallet.Wallet
	inboundTransportEndpoint string
	outboundTransport        transport.OutboundTransport
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

// PackWallet returns the pack wallet service
func (p *Provider) PackWallet() wallet.Pack {
	return p.wallet
}

// DIDWallet returns the pack wallet service
func (p *Provider) DIDWallet() wallet.DIDCreator {
	return p.wallet
}

// InboundTransportEndpoint returns the inbound transport endpoint
func (p *Provider) InboundTransportEndpoint() string {
	return p.inboundTransportEndpoint
}

// InboundMessageHandler return inbound message handler
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(envelope *wallet.Envelope) error {
		// get the message type from the payload and dispatch based on the services
		msgType := &struct {
			Type string `json:"@type,omitempty"`
		}{}
		err := json.Unmarshal(envelope.Message, msgType)
		if err != nil {
			return fmt.Errorf("invalid payload data format: %w", err)
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msgType.Type) {
				return svc.Handle(&service.DIDCommMsg{Type: msgType.Type, Payload: envelope.Message, ToVerKeys: envelope.ToVerKeys})
			}
		}
		return fmt.Errorf("no message handlers found for the message type: %s", msgType.Type)
	}
}

// StorageProvider return storage provider
func (p *Provider) StorageProvider() storage.Provider {
	return p.storeProvider
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
