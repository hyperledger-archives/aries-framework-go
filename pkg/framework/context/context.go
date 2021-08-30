/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cenkalti/backoff/v4"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const defaultGetDIDsMaxRetries = 3

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

func (p *Provider) tryToHandle(
	svc service.InboundHandler, msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	if err := p.messenger.HandleInbound(msg, ctx); err != nil {
		return fmt.Errorf("messenger HandleInbound: %w", err)
	}

	_, err := svc.HandleInbound(msg, ctx)

	return err
}

// InboundMessageHandler return an inbound message handler.
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		msg, err := service.ParseDIDCommMsgMap(envelope.Message)
		if err != nil {
			return err
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msg.Type()) {
				var myDID, theirDID string

				switch svc.Name() {
				// perf: DID exchange doesn't require myDID and theirDID
				case didexchange.DIDExchange:
				default:
					myDID, theirDID, err = p.getDIDs(envelope)
					if err != nil {
						return fmt.Errorf("inbound message handler: %w", err)
					}
				}

				_, err = svc.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))

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
				myDID, theirDID, err := p.getDIDs(envelope)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}

				return p.tryToHandle(svc, msg, service.NewDIDCommContext(myDID, theirDID, nil))
			}
		}

		return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
	}
}

//nolint:gocyclo,nestif
func (p *Provider) getDIDs(envelope *transport.Envelope) (string, string, error) {
	var (
		myDID    string
		theirDID string
		err      error
	)

	return myDID, theirDID, backoff.Retry(func() error {
		var notFound bool

		kaIdentifier := []byte("#")

		if id := bytes.Index(envelope.ToKey, kaIdentifier); id > 0 && bytes.HasPrefix(envelope.ToKey, []byte("did:")) {
			myDID = string(envelope.ToKey[:id])
		} else {
			myDID, err = p.didConnectionStore.GetDID(base58.Encode(envelope.ToKey))
			if errors.Is(err, did.ErrNotFound) {
				notFound = true

				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers only, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.ToKey)
				myDID, err = p.didConnectionStore.GetDID(didKey)
				if errors.Is(err, did.ErrNotFound) {
					notFound = true
				} else if err != nil {
					return fmt.Errorf("failed to get my did from didKey: %w", err)
				}
			} else if err != nil {
				return fmt.Errorf("failed to get my did: %w", err)
			}
		}

		if id := bytes.Index(envelope.FromKey, kaIdentifier); id > 0 && bytes.HasPrefix(envelope.FromKey, []byte("did:")) {
			myDID = string(envelope.FromKey[:id])
		} else {
			theirDID, err = p.didConnectionStore.GetDID(base58.Encode(envelope.FromKey))
			if notFound && errors.Is(err, did.ErrNotFound) {
				// try did:key
				// CreateDIDKey below is for Ed25519 keys only, use the more general CreateDIDKeyByCode if other key
				// types will be used. Currently, did:key is for legacy packers, so only support Ed25519 keys.
				didKey, _ := fingerprint.CreateDIDKey(envelope.FromKey)
				theirDID, err = p.didConnectionStore.GetDID(didKey)
				if err != nil && !errors.Is(err, did.ErrNotFound) {
					return fmt.Errorf("failed to get their did from didKey: %w", err)
				}
			} else if err != nil {
				return fmt.Errorf("failed to get their did: %w", err)
			}
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(p.getDIDsBackOffDuration), p.getDIDsMaxRetries))
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
