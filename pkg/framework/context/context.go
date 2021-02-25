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
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// package context creates a framework Provider context to add optional (non default) framework services and provides
// simple accessor methods to those same services.

// Provider supplies the framework configuration to client objects.
type Provider struct {
	services                   []dispatcher.ProtocolService
	msgSvcProvider             api.MessageServiceProvider
	storeProvider              storage.Provider
	protocolStateStoreProvider storage.Provider
	kms                        kms.KeyManager
	secretLock                 secretlock.Service
	crypto                     crypto.Crypto
	packager                   commontransport.Packager
	primaryPacker              packer.Packer
	packers                    []packer.Packer
	serviceEndpoint            string
	routerEndpoint             string
	outboundDispatcher         dispatcher.Outbound
	messenger                  service.MessengerHandler
	outboundTransports         []transport.OutboundTransport
	vdr                        vdrapi.Registry
	verifiableStore            verifiable.Store
	transportReturnRoute       string
	frameworkID                string
}

type outboundHandler struct {
	services []dispatcher.ProtocolService
}

func (o *outboundHandler) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	for _, s := range o.services {
		if s.Accept(msg.Type()) {
			return s.HandleOutbound(msg, myDID, theirDID)
		}
	}

	return "", fmt.Errorf("no handlers for msg type %s", msg.Type())
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

// Service return protocol service.
func (p *Provider) Service(id string) (interface{}, error) {
	for _, v := range p.services {
		if v.Name() == id {
			return v, nil
		}
	}

	return nil, api.ErrSvcNotFound
}

// KMS returns a Key Management Service.
func (p *Provider) KMS() kms.KeyManager {
	return p.kms
}

// SecretLock returns a secret lock service.
func (p *Provider) SecretLock() secretlock.Service {
	return p.secretLock
}

// Crypto returns the Crypto service.
func (p *Provider) Crypto() crypto.Crypto {
	return p.crypto
}

// Packager returns a packager service.
func (p *Provider) Packager() commontransport.Packager {
	return p.packager
}

// Messenger returns a messenger.
func (p *Provider) Messenger() service.Messenger {
	return p.messenger
}

// Packers returns a list of enabled packers.
func (p *Provider) Packers() []packer.Packer {
	return p.packers
}

// PrimaryPacker returns the main inbound/outbound Packer service.
func (p *Provider) PrimaryPacker() packer.Packer {
	return p.primaryPacker
}

// ServiceEndpoint returns an service endpoint. This endpoint is used in Out-Of-Band messages,
// DID Exchange Invitations or DID Document service to send messages to the agent.
func (p *Provider) ServiceEndpoint() string {
	return p.serviceEndpoint
}

// RouterEndpoint returns a router transport endpoint. The router gives this
// endpoint to the requester agent during route registration. The requester
// agent can use as it's service endpoint. The router checks the forward
// message to routes the message based on the recipient keys(if registered).
func (p *Provider) RouterEndpoint() string {
	return p.routerEndpoint
}

func (p *Provider) tryToHandle(svc service.InboundHandler, msg service.DIDCommMsgMap, myDID, theirDID string) error {
	if err := p.messenger.HandleInbound(msg, myDID, theirDID); err != nil {
		return fmt.Errorf("messenger HandleInbound: %w", err)
	}

	_, err := svc.HandleInbound(msg, myDID, theirDID)

	return err
}

// InboundMessageHandler return an inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(message []byte, myDID, theirDID string) error {
		msg, err := service.ParseDIDCommMsgMap(message)
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
				return p.tryToHandle(svc, msg, myDID, theirDID)
			}
		}

		return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
	}
}

// OutboundMessageHandler returns a handler composed of all registered protocol services.
func (p *Provider) OutboundMessageHandler() service.OutboundHandler {
	tmp := make([]dispatcher.ProtocolService, len(p.services))
	copy(tmp, p.services)

	return &outboundHandler{services: tmp}
}

// StorageProvider return a storage provider.
func (p *Provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

// ProtocolStateStorageProvider return a protocol state storage provider.
func (p *Provider) ProtocolStateStorageProvider() storage.Provider {
	return p.protocolStateStoreProvider
}

// VDRegistry returns a vdr registry.
func (p *Provider) VDRegistry() vdrapi.Registry {
	return p.vdr
}

// TransportReturnRoute returns transport return route.
func (p *Provider) TransportReturnRoute() string {
	return p.transportReturnRoute
}

// AriesFrameworkID returns an inbound transport endpoint.
func (p *Provider) AriesFrameworkID() string {
	return p.frameworkID
}

// VerifiableStore returns a verifiable credential store.
func (p *Provider) VerifiableStore() verifiable.Store {
	return p.verifiableStore
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

// WithMessengerHandler injects the messenger into the context.
func WithMessengerHandler(mh service.MessengerHandler) ProviderOption {
	return func(opts *Provider) error {
		opts.messenger = mh
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
func WithKMS(k kms.KeyManager) ProviderOption {
	return func(opts *Provider) error {
		opts.kms = k
		return nil
	}
}

// WithSecretLock injects a secret lock service into the context.
func WithSecretLock(s secretlock.Service) ProviderOption {
	return func(opts *Provider) error {
		opts.secretLock = s
		return nil
	}
}

// WithCrypto injects a Crypto service into the context.
func WithCrypto(c crypto.Crypto) ProviderOption {
	return func(opts *Provider) error {
		opts.crypto = c
		return nil
	}
}

// WithVDRegistry injects a vdr service into the context.
func WithVDRegistry(vdr vdrapi.Registry) ProviderOption {
	return func(opts *Provider) error {
		opts.vdr = vdr
		return nil
	}
}

// WithServiceEndpoint injects an service transport endpoint into the context.
func WithServiceEndpoint(endpoint string) ProviderOption {
	return func(opts *Provider) error {
		opts.serviceEndpoint = endpoint
		return nil
	}
}

// WithRouterEndpoint injects an router transport endpoint into the context.
func WithRouterEndpoint(endpoint string) ProviderOption {
	return func(opts *Provider) error {
		opts.routerEndpoint = endpoint
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

// WithProtocolStateStorageProvider injects a protocol state storage provider into the context.
func WithProtocolStateStorageProvider(s storage.Provider) ProviderOption {
	return func(opts *Provider) error {
		opts.protocolStateStoreProvider = s
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

// WithMessageServiceProvider injects a message service provider into the context.
func WithMessageServiceProvider(msv api.MessageServiceProvider) ProviderOption {
	return func(opts *Provider) error {
		opts.msgSvcProvider = msv
		return nil
	}
}

// WithVerifiableStore injects a verifiable credential store.
func WithVerifiableStore(store verifiable.Store) ProviderOption {
	return func(opts *Provider) error {
		opts.verifiableStore = store
		return nil
	}
}
