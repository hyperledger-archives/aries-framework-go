/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package context creates a framework Provider context to add optional (non default) framework services and provides
// simple accessor methods to those same services.
package context

import (
	"fmt"
	"time"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/inbound"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	defaultGetDIDsMaxRetries = 3
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	services                   []dispatcher.ProtocolService
	servicesMsgTypeTargets     []dispatcher.MessageTypeTarget
	msgSvcProvider             api.MessageServiceProvider
	storeProvider              storage.Provider
	protocolStateStoreProvider storage.Provider
	kms                        kms.KeyManager
	secretLock                 secretlock.Service
	crypto                     crypto.Crypto
	packager                   transport.Packager
	primaryPacker              packer.Packer
	packers                    []packer.Packer
	serviceEndpoint            string
	routerEndpoint             string
	outboundDispatcher         dispatcher.Outbound
	messenger                  service.MessengerHandler
	outboundTransports         []transport.OutboundTransport
	vdr                        vdrapi.Registry
	verifiableStore            verifiable.Store
	didConnectionStore         did.ConnectionStore
	contextStore               ld.ContextStore
	remoteProviderStore        ld.RemoteProviderStore
	documentLoader             jsonld.DocumentLoader
	transportReturnRoute       string
	frameworkID                string
	keyType                    kms.KeyType
	keyAgreementType           kms.KeyType
	mediaTypeProfiles          []string
	getDIDsMaxRetries          uint64
	getDIDsBackOffDuration     time.Duration
	inboundEnvelopeHandler     InboundEnvelopeHandler
	didRotator                 *middleware.DIDCommMessageMiddleware
	connectionRecorder         *connection.Recorder
}

// InboundEnvelopeHandler handles inbound envelopes, processing then dispatching to a protocol service based on the
// message type.
type InboundEnvelopeHandler interface {
	// HandleInboundEnvelope handles an inbound envelope.
	HandleInboundEnvelope(envelope *transport.Envelope) error
	// HandlerFunc provides the transport.InboundMessageHandler of the given InboundEnvelopeHandler.
	HandlerFunc() transport.InboundMessageHandler
}

type inboundHandler struct {
	handlers []dispatcher.ProtocolService
}

func (in *inboundHandler) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	for i := range in.handlers {
		if in.handlers[i].Accept(msg.Type()) {
			return in.handlers[i].HandleInbound(msg, ctx)
		}
	}

	return "", fmt.Errorf("no inbound handlers for msg type: %s", msg.Type())
}

// New instantiates a new context provider.
func New(opts ...ProviderOption) (*Provider, error) {
	ctxProvider := Provider{
		getDIDsMaxRetries:      defaultGetDIDsMaxRetries,
		getDIDsBackOffDuration: time.Second,
	}

	for _, opt := range opts {
		err := opt(&ctxProvider)
		if err != nil {
			return nil, fmt.Errorf("option failed: %w", err)
		}
	}

	if ctxProvider.storeProvider != nil && ctxProvider.protocolStateStoreProvider != nil {
		recorder, err := connection.NewRecorder(&ctxProvider)
		if err != nil {
			return nil, fmt.Errorf("initialize context connection recorder: %w", err)
		}

		ctxProvider.connectionRecorder = recorder
	}

	return &ctxProvider, nil
}

// ConnectionLookup returns a connection.Lookup initialized on this context's stores.
func (p *Provider) ConnectionLookup() *connection.Lookup {
	return p.connectionRecorder.Lookup
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

// AllServices returns a copy of the Provider's list of ProtocolServices.
func (p *Provider) AllServices() []dispatcher.ProtocolService {
	ret := make([]dispatcher.ProtocolService, len(p.services))

	for i, s := range p.services {
		ret[i] = s
	}

	return ret
}

// ServiceMsgTypeTargets returns list of service message types of context protocol services based mapping for
// the given targets.
func (p *Provider) ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget {
	return p.servicesMsgTypeTargets
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
func (p *Provider) Packager() transport.Packager {
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

// MessageServiceProvider returns a provider of message services.
func (p *Provider) MessageServiceProvider() api.MessageServiceProvider {
	return p.msgSvcProvider
}

// InboundMessageHandler return an inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	if p.inboundEnvelopeHandler == nil {
		p.inboundEnvelopeHandler = inbound.NewInboundMessageHandler(p)
	}

	return p.inboundEnvelopeHandler.HandlerFunc()
}

// DIDRotator returns the didcomm/v2 connection DID rotation service.
func (p *Provider) DIDRotator() *middleware.DIDCommMessageMiddleware {
	return p.didRotator
}

// InboundDIDCommMessageHandler provides a supplier of inbound handlers with all loaded protocol services.
func (p *Provider) InboundDIDCommMessageHandler() func() service.InboundHandler {
	return func() service.InboundHandler {
		tmp := make([]dispatcher.ProtocolService, len(p.services))
		copy(tmp, p.services)

		return &inboundHandler{handlers: tmp}
	}
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

// DIDConnectionStore returns a DID connection store.
func (p *Provider) DIDConnectionStore() did.ConnectionStore {
	return p.didConnectionStore
}

// JSONLDContextStore returns a JSON-LD context store.
func (p *Provider) JSONLDContextStore() ld.ContextStore {
	return p.contextStore
}

// JSONLDRemoteProviderStore returns a remote JSON-LD context provider store.
func (p *Provider) JSONLDRemoteProviderStore() ld.RemoteProviderStore {
	return p.remoteProviderStore
}

// JSONLDDocumentLoader returns a JSON-LD document loader.
func (p *Provider) JSONLDDocumentLoader() jsonld.DocumentLoader {
	return p.documentLoader
}

// KeyType returns the default Key type (signing/authentication).
func (p *Provider) KeyType() kms.KeyType {
	return p.keyType
}

// KeyAgreementType returns the default Key type (encryption).
func (p *Provider) KeyAgreementType() kms.KeyType {
	return p.keyAgreementType
}

// MediaTypeProfiles returns the default media types profile.
func (p *Provider) MediaTypeProfiles() []string {
	return p.mediaTypeProfiles
}

// GetDIDsMaxRetries returns get DIDs max retries.
func (p *Provider) GetDIDsMaxRetries() uint64 {
	return p.getDIDsMaxRetries
}

// GetDIDsBackOffDuration returns get DIDs backoff duration.
func (p *Provider) GetDIDsBackOffDuration() time.Duration {
	return p.getDIDsBackOffDuration
}

// InboundMessenger returns inbound messenger.
func (p *Provider) InboundMessenger() service.InboundMessenger {
	return p.messenger
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

// WithGetDIDsMaxRetries sets max retries.
func WithGetDIDsMaxRetries(retries uint64) ProviderOption {
	return func(opts *Provider) error {
		opts.getDIDsMaxRetries = retries
		return nil
	}
}

// WithGetDIDsBackOffDuration sets backoff duration.
func WithGetDIDsBackOffDuration(duration time.Duration) ProviderOption {
	return func(opts *Provider) error {
		opts.getDIDsBackOffDuration = duration
		return nil
	}
}

// WithDIDRotator injects a DID rotator into the context.
func WithDIDRotator(didRotator *middleware.DIDCommMessageMiddleware) ProviderOption {
	return func(opts *Provider) error {
		opts.didRotator = didRotator
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

// WithServiceMsgTypeTargets injects service msg type to target mappings in the context.
func WithServiceMsgTypeTargets(msgTypeTargets ...dispatcher.MessageTypeTarget) ProviderOption {
	return func(opts *Provider) error {
		opts.servicesMsgTypeTargets = msgTypeTargets
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
func WithPackager(p transport.Packager) ProviderOption {
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

// WithDIDConnectionStore injects a DID connection store into the context.
func WithDIDConnectionStore(store did.ConnectionStore) ProviderOption {
	return func(opts *Provider) error {
		opts.didConnectionStore = store
		return nil
	}
}

// WithJSONLDContextStore injects a JSON-LD context store into the context.
func WithJSONLDContextStore(store ld.ContextStore) ProviderOption {
	return func(opts *Provider) error {
		opts.contextStore = store
		return nil
	}
}

// WithJSONLDRemoteProviderStore injects a JSON-LD remote provider store into the context.
func WithJSONLDRemoteProviderStore(store ld.RemoteProviderStore) ProviderOption {
	return func(opts *Provider) error {
		opts.remoteProviderStore = store
		return nil
	}
}

// WithJSONLDDocumentLoader injects a JSON-LD document loader into the context.
func WithJSONLDDocumentLoader(loader jsonld.DocumentLoader) ProviderOption {
	return func(opts *Provider) error {
		opts.documentLoader = loader
		return nil
	}
}

// WithKeyType injects a keyType for authentication (signing) into the context.
func WithKeyType(keyType kms.KeyType) ProviderOption {
	return func(opts *Provider) error {
		switch keyType {
		case kms.ED25519Type, kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363,
			kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER, kms.BLS12381G2Type:
			opts.keyType = keyType
			return nil
		default:
			return fmt.Errorf("invalid authentication key type: %s", keyType)
		}
	}
}

// WithKeyAgreementType injects a keyType for KeyAgreement into the context.
func WithKeyAgreementType(keyAgreementType kms.KeyType) ProviderOption {
	return func(opts *Provider) error {
		switch keyAgreementType {
		case kms.X25519ECDHKWType, kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
			opts.keyAgreementType = keyAgreementType
			return nil
		default:
			return fmt.Errorf("invalid KeyAgreement key type: %s", keyAgreementType)
		}
	}
}

// WithMediaTypeProfiles injects a media type profile into the context.
func WithMediaTypeProfiles(mediaTypeProfiles []string) ProviderOption {
	return func(opts *Provider) error {
		opts.mediaTypeProfiles = make([]string, len(mediaTypeProfiles))
		copy(opts.mediaTypeProfiles, mediaTypeProfiles)

		return nil
	}
}

// WithInboundEnvelopeHandler injects a handler for inbound message envelopes.
func WithInboundEnvelopeHandler(handler InboundEnvelopeHandler) ProviderOption {
	return func(opts *Provider) error {
		opts.inboundEnvelopeHandler = handler
		return nil
	}
}
