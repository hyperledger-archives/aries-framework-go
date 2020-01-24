/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	services                 []dispatcher.ProtocolService
	msgSvcProvider           api.MessageServiceProvider
	storeProvider            storage.Provider
	transientStoreProvider   storage.Provider
	kms                      legacykms.KMS
	crypto                   crypto.Crypto
	packager                 commontransport.Packager
	primaryPacker            packer.Packer
	packers                  []packer.Packer
	inboundTransportEndpoint string
	outboundDispatcher       dispatcher.Outbound
	outboundTransports       []transport.OutboundTransport
	vdriRegistry             vdriapi.Registry
	transportReturnRoute     string
	frameworkID              string
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
	return p.outboundTransports
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
func (p *Provider) KMS() legacykms.KeyManager {
	return p.kms
}

// Crypto returns the Crypto service
func (p *Provider) Crypto() crypto.Crypto {
	return p.crypto
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
func (p *Provider) Signer() legacykms.Signer {
	return p.kms
}

// InboundTransportEndpoint returns an inbound transport endpoint.
func (p *Provider) InboundTransportEndpoint() string {
	return p.inboundTransportEndpoint
}

// InboundMessageHandler return an inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte, myDID, theirDID string) error {
		msg, err := service.NewDIDCommMsgMap(message)
		if err != nil {
			return err
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msg.Type()) {
				_, err = svc.HandleInbound(msg, myDID, theirDID)
				return err
			}
		}

		// in case of no services are registered for given message type,
		// find generic inbound services registered for given message header
		for _, svc := range p.msgSvcProvider.Services() {
			h := struct {
				Purpose []string `json:"~purpose"`
			}{}
			err = msg.Decode(&h)

			if err != nil {
				return err
			}

			if svc.Accept(msg.Type(), h.Purpose) {
				_, err = svc.HandleInbound(msg, myDID, theirDID)
				return err
			}
		}

		return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
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

// VDRIRegistry returns a vdri registry
func (p *Provider) VDRIRegistry() vdriapi.Registry {
	return p.vdriRegistry
}

// TransportReturnRoute returns transport return route
func (p *Provider) TransportReturnRoute() string {
	return p.transportReturnRoute
}

// AriesFrameworkID returns an inbound transport endpoint.
func (p *Provider) AriesFrameworkID() string {
	return p.frameworkID
}

// ProviderOption configures the framework.
type ProviderOption func(opts *Provider) error

// WithOutboundTransports injects an outbound transports into the context.
func WithOutboundTransports(transports ...transport.OutboundTransport) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundTransports = transports
		return nil
	}
}

// WithOutboundDispatcher injects an outbound dispatcher into the context.
func WithOutboundDispatcher(outboundDispatcher dispatcher.Outbound) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundDispatcher = outboundDispatcher
		return nil
	}
}

// WithTransportReturnRoute injects transport return route option to the Aries framework.
func WithTransportReturnRoute(transportReturnRoute string) ProviderOption {
	return func(opts *Provider) error {
		opts.transportReturnRoute = transportReturnRoute
		return nil
	}
}

// WithProtocolServices injects a protocol services into the context.
func WithProtocolServices(services ...dispatcher.ProtocolService) ProviderOption {
	return func(opts *Provider) error {
		opts.services = services
		return nil
	}
}

// WithKMS injects a kms service into the context.
func WithKMS(w legacykms.KMS) ProviderOption {
	return func(opts *Provider) error {
		opts.kms = w
		return nil
	}
}

// WithCrypto injects a Crypto service into the context
func WithCrypto(c crypto.Crypto) ProviderOption {
	return func(opts *Provider) error {
		opts.crypto = c
		return nil
	}
}

// WithVDRIRegistry injects a vdri service into the context.
func WithVDRIRegistry(vdri vdriapi.Registry) ProviderOption {
	return func(opts *Provider) error {
		opts.vdriRegistry = vdri
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

// WithAriesFrameworkID injects the framework ID into the context. This is used to tie different framework components.
// The client can have multiple framework and with same instance of transport shared across it and this id is used
// by the framework to tie the inbound transport and outbound transports (in case of duplex communication).
func WithAriesFrameworkID(id string) ProviderOption {
	return func(opts *Provider) error {
		opts.frameworkID = id
		return nil
	}
}

// WithMessageServiceProvider injects a message service provider into the context
func WithMessageServiceProvider(msv api.MessageServiceProvider) ProviderOption {
	return func(opts *Provider) error {
		opts.msgSvcProvider = msv
		return nil
	}
}
