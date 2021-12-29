/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/inbound"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/outbound"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	defaultEndpoint     = "didcomm:transport/queue"
	defaultMasterKeyURI = "local-lock://default/master/key/"
)

// Aries provides access to the context being managed by the framework. The context can be used to create aries clients.
type Aries struct {
	storeProvider              storage.Provider
	protocolStateStoreProvider storage.Provider
	protocolSvcCreators        []api.ProtocolSvcCreator
	services                   []dispatcher.ProtocolService
	servicesMsgTypeTargets     []dispatcher.MessageTypeTarget
	msgSvcProvider             api.MessageServiceProvider
	outboundDispatcher         dispatcher.Outbound
	messenger                  service.MessengerHandler
	outboundTransports         []transport.OutboundTransport
	inboundTransports          []transport.InboundTransport
	kms                        kms.KeyManager
	kmsCreator                 kms.Creator
	secretLock                 secretlock.Service
	crypto                     crypto.Crypto
	packagerCreator            packager.Creator
	packager                   transport.Packager
	packerCreator              packer.Creator
	packerCreators             []packer.Creator
	primaryPacker              packer.Packer
	packers                    []packer.Packer
	vdrRegistry                vdrapi.Registry
	vdr                        []vdrapi.VDR
	verifiableStore            verifiable.Store
	didConnectionStore         did.ConnectionStore
	contextStore               ldstore.ContextStore
	remoteProviderStore        ldstore.RemoteProviderStore
	documentLoader             jsonld.DocumentLoader
	contextProviderURLs        []string
	transportReturnRoute       string
	id                         string
	keyType                    kms.KeyType
	keyAgreementType           kms.KeyType
	mediaTypeProfiles          []string
	inboundEnvelopeHandler     inbound.MessageHandler
	didRotator                 middleware.DIDCommMessageMiddleware
}

// Option configures the framework.
type Option func(opts *Aries) error

// New initializes the Aries framework based on the set of options provided. This function returns a framework
// which can be used to manage Aries clients by getting the framework context.
func New(opts ...Option) (*Aries, error) {
	frameworkOpts := &Aries{}

	// generate framework configs from options
	for _, option := range opts {
		err := option(frameworkOpts)
		if err != nil {
			closeErr := frameworkOpts.Close()
			return nil, fmt.Errorf("close err: %v Error in option passed to New: %w", closeErr, err)
		}
	}

	// generate a random framework ID
	frameworkOpts.id = uuid.New().String()

	// get the default framework options
	err := defFrameworkOpts(frameworkOpts)
	if err != nil {
		return nil, fmt.Errorf("default option initialization failed: %w", err)
	}

	// TODO: https://github.com/hyperledger/aries-framework-go/issues/212
	//  Define clear relationship between framework and context.
	//  Details - The code creates context without protocolServices. The protocolServicesCreators are dependent
	//  on the context. The inbound transports require ctx.MessageHandler(), which in-turn depends on
	//  protocolServices. At the moment, there is a looping issue among these.

	return initializeServices(frameworkOpts)
}

func initializeServices(frameworkOpts *Aries) (*Aries, error) {
	// Order of initializing service is important
	// Create kms
	if e := createKMS(frameworkOpts); e != nil {
		return nil, e
	}

	// Create vdr
	if e := createVDR(frameworkOpts); e != nil {
		return nil, e
	}

	// create packers and packager (must be done after KMS and connection store)
	if err := createPackersAndPackager(frameworkOpts); err != nil {
		return nil, err
	}

	// Create DID rotator
	if err := createDIDRotator(frameworkOpts); err != nil {
		return nil, err
	}

	// Create outbound dispatcher
	if err := createOutboundDispatcher(frameworkOpts); err != nil {
		return nil, err
	}

	// Create messenger handler
	if err := createMessengerHandler(frameworkOpts); err != nil {
		return nil, err
	}

	// Create DID connection store
	if err := createDIDConnectionStore(frameworkOpts); err != nil {
		return nil, err
	}

	// Load services
	if err := loadServices(frameworkOpts); err != nil {
		return nil, err
	}

	// Start inbound/outbound transports
	if err := startTransports(frameworkOpts); err != nil {
		return nil, err
	}

	return frameworkOpts, nil
}

// WithMessengerHandler injects a messenger handler to the Aries framework.
func WithMessengerHandler(mh service.MessengerHandler) Option {
	return func(opts *Aries) error {
		opts.messenger = mh
		return nil
	}
}

// WithOutboundTransports injects an outbound transports to the Aries framework.
func WithOutboundTransports(outboundTransports ...transport.OutboundTransport) Option {
	return func(opts *Aries) error {
		opts.outboundTransports = append(opts.outboundTransports, outboundTransports...)
		return nil
	}
}

// WithInboundTransport injects an inbound transport to the Aries framework.
func WithInboundTransport(inboundTransport ...transport.InboundTransport) Option {
	return func(opts *Aries) error {
		opts.inboundTransports = append(opts.inboundTransports, inboundTransport...)
		return nil
	}
}

// WithTransportReturnRoute injects transport return route option to the Aries framework. Acceptable values - "none",
// "all" or "thread". RFC - https://github.com/hyperledger/aries-rfcs/tree/master/features/0092-transport-return-route.
// Currently, framework supports "all" and "none" option with WebSocket transport ("thread" is not supported).
func WithTransportReturnRoute(transportReturnRoute string) Option {
	return func(opts *Aries) error {
		//  "thread" option is not supported at the moment.
		if transportReturnRoute != decorator.TransportReturnRouteNone &&
			transportReturnRoute != decorator.TransportReturnRouteAll {
			return fmt.Errorf("invalid transport return route option : %s", transportReturnRoute)
		}

		opts.transportReturnRoute = transportReturnRoute

		return nil
	}
}

// WithStoreProvider injects a storage provider to the Aries framework.
func WithStoreProvider(prov storage.Provider) Option {
	return func(opts *Aries) error {
		opts.storeProvider = prov
		return nil
	}
}

// WithProtocolStateStoreProvider injects a protocol state storage provider to the Aries framework.
func WithProtocolStateStoreProvider(prov storage.Provider) Option {
	return func(opts *Aries) error {
		opts.protocolStateStoreProvider = prov
		return nil
	}
}

// WithProtocols injects a protocol service to the Aries framework.
func WithProtocols(protocolSvcCreator ...api.ProtocolSvcCreator) Option {
	return func(opts *Aries) error {
		opts.protocolSvcCreators = append(opts.protocolSvcCreators, protocolSvcCreator...)
		return nil
	}
}

// WithSecretLock injects a SecretLock service to the Aries framework.
func WithSecretLock(s secretlock.Service) Option {
	return func(opts *Aries) error {
		opts.secretLock = s
		return nil
	}
}

// WithKMS injects a KMS service to the Aries framework.
func WithKMS(k kms.Creator) Option {
	return func(opts *Aries) error {
		opts.kmsCreator = k
		return nil
	}
}

// WithCrypto injects a crypto service to the Aries framework.
func WithCrypto(c crypto.Crypto) Option {
	return func(opts *Aries) error {
		opts.crypto = c
		return nil
	}
}

// WithVDR injects a VDR service to the Aries framework.
func WithVDR(v vdrapi.VDR) Option {
	return func(opts *Aries) error {
		opts.vdr = append(opts.vdr, v)
		return nil
	}
}

// WithMessageServiceProvider injects a message service provider to the Aries framework.
// Message service provider returns list of message services which can be used to provide custom handle
// functionality based on incoming messages type and purpose.
func WithMessageServiceProvider(msv api.MessageServiceProvider) Option {
	return func(opts *Aries) error {
		opts.msgSvcProvider = msv
		return nil
	}
}

// WithPacker injects at least one Packer service into the Aries framework,
// with the primary Packer being used for inbound/outbound communication
// and the additional packers being available for unpacking inbound messages.
func WithPacker(primary packer.Creator, additionalPackers ...packer.Creator) Option {
	return func(opts *Aries) error {
		opts.packerCreator = primary
		opts.packerCreators = append(opts.packerCreators, additionalPackers...)

		return nil
	}
}

// WithVerifiableStore injects a verifiable credential store.
func WithVerifiableStore(store verifiable.Store) Option {
	return func(opts *Aries) error {
		opts.verifiableStore = store
		return nil
	}
}

// WithDIDConnectionStore injects a DID connection store.
func WithDIDConnectionStore(store did.ConnectionStore) Option {
	return func(opts *Aries) error {
		opts.didConnectionStore = store
		return nil
	}
}

// WithJSONLDContextStore injects a JSON-LD context store.
func WithJSONLDContextStore(store ldstore.ContextStore) Option {
	return func(opts *Aries) error {
		opts.contextStore = store
		return nil
	}
}

// WithJSONLDRemoteProviderStore injects a JSON-LD remote provider store.
func WithJSONLDRemoteProviderStore(store ldstore.RemoteProviderStore) Option {
	return func(opts *Aries) error {
		opts.remoteProviderStore = store
		return nil
	}
}

// WithJSONLDDocumentLoader injects a JSON-LD document loader.
func WithJSONLDDocumentLoader(loader jsonld.DocumentLoader) Option {
	return func(opts *Aries) error {
		opts.documentLoader = loader
		return nil
	}
}

// WithJSONLDContextProviderURL injects URLs of the remote JSON-LD context providers.
func WithJSONLDContextProviderURL(url ...string) Option {
	return func(opts *Aries) error {
		opts.contextProviderURLs = append(opts.contextProviderURLs, url...)
		return nil
	}
}

// WithKeyType injects a default signing key type.
func WithKeyType(keyType kms.KeyType) Option {
	return func(opts *Aries) error {
		opts.keyType = keyType
		return nil
	}
}

// WithKeyAgreementType injects a default encryption key type.
func WithKeyAgreementType(keyAgreementType kms.KeyType) Option {
	return func(opts *Aries) error {
		opts.keyAgreementType = keyAgreementType
		return nil
	}
}

// WithMediaTypeProfiles injects a default media types profile.
func WithMediaTypeProfiles(mediaTypeProfiles []string) Option {
	return func(opts *Aries) error {
		opts.mediaTypeProfiles = make([]string, len(mediaTypeProfiles))
		copy(opts.mediaTypeProfiles, mediaTypeProfiles)

		return nil
	}
}

// WithServiceMsgTypeTargets injects service msg type to target mappings in the context.
func WithServiceMsgTypeTargets(msgTypeTargets ...dispatcher.MessageTypeTarget) Option {
	return func(opts *Aries) error {
		opts.servicesMsgTypeTargets = msgTypeTargets
		return nil
	}
}

// Context provides a handle to the framework context.
func (a *Aries) Context() (*context.Provider, error) {
	return context.New(
		context.WithOutboundDispatcher(a.outboundDispatcher),
		context.WithMessengerHandler(a.messenger),
		context.WithOutboundTransports(a.outboundTransports...),
		context.WithProtocolServices(a.services...),
		context.WithKMS(a.kms),
		context.WithSecretLock(a.secretLock),
		context.WithCrypto(a.crypto),
		context.WithServiceEndpoint(serviceEndpoint(a)),
		context.WithRouterEndpoint(routingEndpoint(a)),
		context.WithStorageProvider(a.storeProvider),
		context.WithProtocolStateStorageProvider(a.protocolStateStoreProvider),
		context.WithPacker(a.primaryPacker, a.packers...),
		context.WithPackager(a.packager),
		context.WithVDRegistry(a.vdrRegistry),
		context.WithTransportReturnRoute(a.transportReturnRoute),
		context.WithAriesFrameworkID(a.id),
		context.WithMessageServiceProvider(a.msgSvcProvider),
		context.WithVerifiableStore(a.verifiableStore),
		context.WithDIDConnectionStore(a.didConnectionStore),
		context.WithJSONLDContextStore(a.contextStore),
		context.WithJSONLDRemoteProviderStore(a.remoteProviderStore),
		context.WithJSONLDDocumentLoader(a.documentLoader),
		context.WithKeyType(a.keyType),
		context.WithKeyAgreementType(a.keyAgreementType),
		context.WithMediaTypeProfiles(a.mediaTypeProfiles),
		context.WithServiceMsgTypeTargets(a.servicesMsgTypeTargets...),
		context.WithDIDRotator(&a.didRotator),
		context.WithInboundEnvelopeHandler(&a.inboundEnvelopeHandler),
	)
}

// Messenger returns messenger for sending messages through this agent framework
// TODO should use dedicated messenger interface instead of Outbound dispatcher [Issue #1058].
func (a *Aries) Messenger() service.Messenger {
	return a.messenger
}

// Close frees resources being maintained by the framework.
func (a *Aries) Close() error {
	if a.storeProvider != nil {
		err := a.storeProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	if a.protocolStateStoreProvider != nil {
		err := a.protocolStateStoreProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	for _, inbound := range a.inboundTransports {
		if err := inbound.Stop(); err != nil {
			return fmt.Errorf("inbound transport close failed: %w", err)
		}
	}

	return a.closeVDR()
}

func (a *Aries) closeVDR() error {
	if a.vdrRegistry != nil {
		if err := a.vdrRegistry.Close(); err != nil {
			return fmt.Errorf("vdr registry close failed: %w", err)
		}
	}

	return nil
}

func createKMS(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithSecretLock(frameworkOpts.secretLock),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	frameworkOpts.kms, err = frameworkOpts.kmsCreator(ctx)
	if err != nil {
		return fmt.Errorf("create KMS failed: %w", err)
	}

	return nil
}

func createVDR(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithServiceEndpoint(serviceEndpoint(frameworkOpts)),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	var opts []vdr.Option
	for _, v := range frameworkOpts.vdr {
		opts = append(opts, vdr.WithVDR(v))
	}

	p, err := peer.New(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("create new vdr peer failed: %w", err)
	}

	dst := vdrapi.DIDCommServiceType

	for _, mediaType := range frameworkOpts.mediaTypeProfiles {
		if mediaType == transport.MediaTypeDIDCommV2Profile || mediaType == transport.MediaTypeAIP2RFC0587Profile {
			dst = vdrapi.DIDCommV2ServiceType
			break
		}
	}

	opts = append(opts,
		vdr.WithVDR(p),
		vdr.WithDefaultServiceType(dst),
		vdr.WithDefaultServiceEndpoint(ctx.ServiceEndpoint()),
	)

	k := key.New()
	opts = append(opts, vdr.WithVDR(k))

	frameworkOpts.vdrRegistry = vdr.New(opts...)

	return nil
}

func createMessengerHandler(frameworkOpts *Aries) error {
	if frameworkOpts.messenger != nil {
		return nil
	}

	ctx, err := context.New(
		context.WithOutboundDispatcher(frameworkOpts.outboundDispatcher),
		context.WithStorageProvider(frameworkOpts.storeProvider),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	frameworkOpts.messenger, err = messenger.NewMessenger(ctx)

	return err
}

func createDIDRotator(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithVDRegistry(frameworkOpts.vdrRegistry),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithProtocolStateStorageProvider(frameworkOpts.protocolStateStoreProvider),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	dr, err := middleware.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to init did rotator: %w", err)
	}

	frameworkOpts.didRotator = *dr

	return nil
}

func createOutboundDispatcher(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithOutboundTransports(frameworkOpts.outboundTransports...),
		context.WithPackager(frameworkOpts.packager),
		context.WithTransportReturnRoute(frameworkOpts.transportReturnRoute),
		context.WithVDRegistry(frameworkOpts.vdrRegistry),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithProtocolStateStorageProvider(frameworkOpts.protocolStateStoreProvider),
		context.WithMediaTypeProfiles(frameworkOpts.mediaTypeProfiles),
		context.WithKeyAgreementType(frameworkOpts.keyAgreementType),
		context.WithDIDRotator(&frameworkOpts.didRotator),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	frameworkOpts.outboundDispatcher, err = outbound.NewOutbound(ctx)
	if err != nil {
		return fmt.Errorf("failed to init outbound dispatcher: %w", err)
	}

	return nil
}

func createDIDConnectionStore(frameworkOpts *Aries) error {
	if frameworkOpts.didConnectionStore != nil {
		return nil
	}

	ctx, err := context.New(
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithVDRegistry(frameworkOpts.vdrRegistry),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	frameworkOpts.didConnectionStore, err = did.NewConnectionStore(ctx)

	return err
}

func createJSONLDContextStore(frameworkOpts *Aries) error {
	if frameworkOpts.contextStore != nil {
		return nil
	}

	s, err := ldstore.NewContextStore(frameworkOpts.storeProvider)
	if err != nil {
		return fmt.Errorf("failed to init JSON-LD context store: %w", err)
	}

	frameworkOpts.contextStore = s

	return nil
}

func createJSONLDRemoteProviderStore(frameworkOpts *Aries) error {
	if frameworkOpts.remoteProviderStore != nil {
		return nil
	}

	s, err := ldstore.NewRemoteProviderStore(frameworkOpts.storeProvider)
	if err != nil {
		return fmt.Errorf("failed to init JSON-LD remote provider store: %w", err)
	}

	frameworkOpts.remoteProviderStore = s

	return nil
}

func createJSONLDDocumentLoader(frameworkOpts *Aries) error {
	if frameworkOpts.documentLoader != nil {
		return nil
	}

	ctx, err := context.New(
		context.WithJSONLDContextStore(frameworkOpts.contextStore),
		context.WithJSONLDRemoteProviderStore(frameworkOpts.remoteProviderStore),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	var loaderOpts []ld.DocumentLoaderOpts

	if len(frameworkOpts.contextProviderURLs) > 0 {
		for _, url := range frameworkOpts.contextProviderURLs {
			loaderOpts = append(loaderOpts, ld.WithRemoteProvider(remote.NewProvider(url)))
		}
	}

	documentLoader, err := ld.NewDocumentLoader(ctx, loaderOpts...)
	if err != nil {
		return fmt.Errorf("document loader creation failed: %w", err)
	}

	frameworkOpts.documentLoader = documentLoader

	return nil
}

func startTransports(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithCrypto(frameworkOpts.crypto),
		context.WithPackager(frameworkOpts.packager),
		context.WithProtocolServices(frameworkOpts.services...),
		context.WithAriesFrameworkID(frameworkOpts.id),
		context.WithMessageServiceProvider(frameworkOpts.msgSvcProvider),
		context.WithMessengerHandler(frameworkOpts.messenger),
		context.WithDIDConnectionStore(frameworkOpts.didConnectionStore),
		context.WithKeyType(frameworkOpts.keyType),
		context.WithKeyAgreementType(frameworkOpts.keyAgreementType),
		context.WithMediaTypeProfiles(frameworkOpts.mediaTypeProfiles),
		context.WithInboundEnvelopeHandler(&frameworkOpts.inboundEnvelopeHandler),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	for _, inbound := range frameworkOpts.inboundTransports {
		// Start the inbound transport
		if err = inbound.Start(ctx); err != nil {
			return fmt.Errorf("inbound transport start failed: %w", err)
		}
	}

	// Start the outbound transport
	for _, outbound := range frameworkOpts.outboundTransports {
		if err = outbound.Start(ctx); err != nil {
			return fmt.Errorf("outbound transport start failed: %w", err)
		}
	}

	return nil
}

func loadServices(frameworkOpts *Aries) error { // nolint:funlen
	// uninitialized
	frameworkOpts.inboundEnvelopeHandler = inbound.MessageHandler{}

	ctx, err := context.New(
		context.WithOutboundDispatcher(frameworkOpts.outboundDispatcher),
		context.WithMessengerHandler(frameworkOpts.messenger),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithProtocolStateStorageProvider(frameworkOpts.protocolStateStoreProvider),
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithPackager(frameworkOpts.packager),
		context.WithServiceEndpoint(serviceEndpoint(frameworkOpts)),
		context.WithRouterEndpoint(routingEndpoint(frameworkOpts)),
		context.WithVDRegistry(frameworkOpts.vdrRegistry),
		context.WithVerifiableStore(frameworkOpts.verifiableStore),
		context.WithDIDConnectionStore(frameworkOpts.didConnectionStore),
		context.WithMessageServiceProvider(frameworkOpts.msgSvcProvider),
		context.WithJSONLDDocumentLoader(frameworkOpts.documentLoader),
		context.WithKeyType(frameworkOpts.keyType),
		context.WithKeyAgreementType(frameworkOpts.keyAgreementType),
		context.WithMediaTypeProfiles(frameworkOpts.mediaTypeProfiles),
		context.WithInboundEnvelopeHandler(&frameworkOpts.inboundEnvelopeHandler),
		context.WithServiceMsgTypeTargets(frameworkOpts.servicesMsgTypeTargets...),
		context.WithDIDRotator(&frameworkOpts.didRotator),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	for i, v := range frameworkOpts.protocolSvcCreators {
		svc, svcErr := v.Create(ctx)
		if svcErr != nil {
			return fmt.Errorf("new protocol service failed: %w", svcErr)
		}

		frameworkOpts.services = append(frameworkOpts.services, svc)
		// after service was successfully created we need to add it to the context
		// since the introduce protocol depends on did-exchange
		if e := context.WithProtocolServices(frameworkOpts.services...)(ctx); e != nil {
			return e
		}

		frameworkOpts.protocolSvcCreators[i].ServicePointer = svc
	}

	// after adding all protocol services to the context, we can initialize the handler properly.
	frameworkOpts.inboundEnvelopeHandler.Initialize(ctx)

	for _, v := range frameworkOpts.protocolSvcCreators {
		if init := v.Init; init != nil {
			if e := init(v.ServicePointer, ctx); e != nil {
				return e
			}
		} else {
			if e := v.ServicePointer.Initialize(ctx); e != nil {
				return e
			}
		}
	}

	return nil
}

func createPackersAndPackager(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithCrypto(frameworkOpts.crypto),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithKMS(frameworkOpts.kms),
		context.WithVDRegistry(frameworkOpts.vdrRegistry),
	)
	if err != nil {
		return fmt.Errorf("create packer context failed: %w", err)
	}

	frameworkOpts.primaryPacker, err = frameworkOpts.packerCreator(ctx)
	if err != nil {
		return fmt.Errorf("create packer failed: %w", err)
	}

	for _, pC := range frameworkOpts.packerCreators {
		if pC == nil {
			continue
		}

		p, e := pC(ctx)
		if e != nil {
			return fmt.Errorf("create packer failed: %w", e)
		}

		frameworkOpts.packers = append(frameworkOpts.packers, p)
	}

	ctx, err = context.New(context.WithPacker(frameworkOpts.primaryPacker, frameworkOpts.packers...),
		context.WithStorageProvider(frameworkOpts.storeProvider), context.WithVDRegistry(frameworkOpts.vdrRegistry))
	if err != nil {
		return fmt.Errorf("create packager context failed: %w", err)
	}

	frameworkOpts.packager, err = frameworkOpts.packagerCreator(ctx)
	if err != nil {
		return fmt.Errorf("create packager failed: %w", err)
	}

	return nil
}

func serviceEndpoint(frameworkOpts *Aries) string {
	return fetchEndpoint(frameworkOpts, "ws")
}

func routingEndpoint(frameworkOpts *Aries) string {
	return fetchEndpoint(frameworkOpts, "http")
}

func fetchEndpoint(frameworkOpts *Aries, defaultScheme string) string {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/1161 Select Service and Router
	//  endpoint from Multiple Inbound Transports
	for _, inbound := range frameworkOpts.inboundTransports {
		if strings.HasPrefix(inbound.Endpoint(), defaultScheme) {
			return inbound.Endpoint()
		}
	}

	if len(frameworkOpts.inboundTransports) > 0 {
		return frameworkOpts.inboundTransports[0].Endpoint()
	}

	return defaultEndpoint
}
