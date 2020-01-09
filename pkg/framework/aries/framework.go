/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/api/crypto"
	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/peer"
)

const (
	// TODO https://github.com/hyperledger/aries-framework-go/issues/837 - If inbound not present, the endpoint
	//  should be of routing agent
	defaultEndpoint = "routing:endpoint"
)

// Aries provides access to the context being managed by the framework. The context can be used to create aries clients.
type Aries struct {
	storeProvider storage.Provider
	// TODO Rename transient store to protocol state store https://github.com/hyperledger/aries-framework-go/issues/835
	transientStoreProvider storage.Provider
	protocolSvcCreators    []api.ProtocolSvcCreator
	services               []dispatcher.Service
	outboundDispatcher     dispatcher.Outbound
	outboundTransports     []transport.OutboundTransport
	inboundTransport       transport.InboundTransport
	kmsCreator             api.KMSCreator
	kms                    api.CloseableKMS
	crypto                 crypto.Crypto
	packagerCreator        packager.Creator
	packager               commontransport.Packager
	packerCreator          packer.Creator
	packerCreators         []packer.Creator
	primaryPacker          packer.Packer
	packers                []packer.Packer
	vdriRegistry           vdriapi.Registry
	vdri                   []vdriapi.VDRI
	transportReturnRoute   string
	id                     string
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
	//  on the context. The inbound transports require ctx.InboundMessageHandler(), which in-turn depends on
	//  protocolServices. At the moment, there is a looping issue among these.

	return initializeServices(frameworkOpts)
}

func initializeServices(frameworkOpts *Aries) (*Aries, error) {
	// Order of initializing service is important
	// Create kms
	if e := createKMS(frameworkOpts); e != nil {
		return nil, e
	}

	// Create vdri
	if e := createVDRI(frameworkOpts); e != nil {
		return nil, e
	}

	// create packers and packager (must be done after KMS and connection store)
	if err := createPackersAndPackager(frameworkOpts); err != nil {
		return nil, err
	}

	// Create outbound dispatcher
	if err := createOutboundDispatcher(frameworkOpts); err != nil {
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

// WithOutboundTransports injects an outbound transports to the Aries framework.
func WithOutboundTransports(outboundTransports ...transport.OutboundTransport) Option {
	return func(opts *Aries) error {
		opts.outboundTransports = append(opts.outboundTransports, outboundTransports...)
		return nil
	}
}

// WithInboundTransport injects an inbound transport to the Aries framework.
func WithInboundTransport(inboundTransport transport.InboundTransport) Option {
	return func(opts *Aries) error {
		opts.inboundTransport = inboundTransport
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

// WithTransientStoreProvider injects a transient storage provider to the Aries framework.
func WithTransientStoreProvider(prov storage.Provider) Option {
	return func(opts *Aries) error {
		opts.transientStoreProvider = prov
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

// WithKMS injects a KMS service to the Aries framework.
func WithKMS(k api.KMSCreator) Option {
	return func(opts *Aries) error {
		opts.kmsCreator = k
		return nil
	}
}

// WithCrypto injects a crypto service to the Aries framework
func WithCrypto(c crypto.Crypto) Option {
	return func(opts *Aries) error {
		opts.crypto = c
		return nil
	}
}

// WithVDRI injects a VDRI service to the Aries framework.
func WithVDRI(v vdriapi.VDRI) Option {
	return func(opts *Aries) error {
		opts.vdri = append(opts.vdri, v)
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

// Context provides a handle to the framework context.
func (a *Aries) Context() (*context.Provider, error) {
	endPoint := defaultEndpoint
	if a.inboundTransport != nil {
		endPoint = a.inboundTransport.Endpoint()
	}

	return context.New(
		context.WithOutboundDispatcher(a.outboundDispatcher),
		context.WithOutboundTransports(a.outboundTransports...),
		context.WithProtocolServices(a.services...),
		context.WithKMS(a.kms),
		context.WithCrypto(a.crypto),
		context.WithInboundTransportEndpoint(endPoint),
		context.WithStorageProvider(a.storeProvider),
		context.WithTransientStorageProvider(a.transientStoreProvider),
		context.WithPacker(a.primaryPacker, a.packers...),
		context.WithPackager(a.packager),
		context.WithVDRIRegistry(a.vdriRegistry),
		context.WithTransportReturnRoute(a.transportReturnRoute),
		context.WithAriesFrameworkID(a.id),
	)
}

// Close frees resources being maintained by the framework.
func (a *Aries) Close() error {
	if a.kms != nil {
		err := a.kms.Close()
		if err != nil {
			return fmt.Errorf("failed to close the kms: %w", err)
		}
	}

	if a.storeProvider != nil {
		err := a.storeProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	if a.transientStoreProvider != nil {
		err := a.transientStoreProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the store: %w", err)
		}
	}

	if a.inboundTransport != nil {
		if err := a.inboundTransport.Stop(); err != nil {
			return fmt.Errorf("inbound transport close failed: %w", err)
		}
	}

	return a.closeVDRI()
}

func (a *Aries) closeVDRI() error {
	if a.vdriRegistry != nil {
		if err := a.vdriRegistry.Close(); err != nil {
			return fmt.Errorf("vdri registry close failed: %w", err)
		}
	}

	return nil
}

func createKMS(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithStorageProvider(frameworkOpts.storeProvider),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	frameworkOpts.kms, err = frameworkOpts.kmsCreator(ctx)
	if err != nil {
		return fmt.Errorf("create kms failed: %w", err)
	}

	return nil
}

func createVDRI(frameworkOpts *Aries) error {
	endPoint := defaultEndpoint
	if frameworkOpts.inboundTransport != nil {
		endPoint = frameworkOpts.inboundTransport.Endpoint()
	}

	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithInboundTransportEndpoint(endPoint),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	var opts []vdri.Option
	for _, v := range frameworkOpts.vdri {
		opts = append(opts, vdri.WithVDRI(v))
	}

	p, err := peer.New(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("create new vdri peer failed: %w", err)
	}

	opts = append(opts,
		vdri.WithVDRI(p),
		vdri.WithDefaultServiceType(vdriapi.DIDCommServiceType),
		vdri.WithDefaultServiceEndpoint(ctx.InboundTransportEndpoint()),
	)

	frameworkOpts.vdriRegistry = vdri.New(ctx, opts...)

	return nil
}

func createOutboundDispatcher(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithOutboundTransports(frameworkOpts.outboundTransports...),
		context.WithPackager(frameworkOpts.packager),
		context.WithTransportReturnRoute(frameworkOpts.transportReturnRoute),
		context.WithVDRIRegistry(frameworkOpts.vdriRegistry),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	frameworkOpts.outboundDispatcher = dispatcher.NewOutbound(ctx)

	return nil
}

func startTransports(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithPackager(frameworkOpts.packager),
		context.WithProtocolServices(frameworkOpts.services...),
		context.WithAriesFrameworkID(frameworkOpts.id),
	)
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	if frameworkOpts.inboundTransport != nil {
		// Start the inbound transport
		if err = frameworkOpts.inboundTransport.Start(ctx); err != nil {
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

func loadServices(frameworkOpts *Aries) error {
	endPoint := defaultEndpoint
	if frameworkOpts.inboundTransport != nil {
		endPoint = frameworkOpts.inboundTransport.Endpoint()
	}

	ctx, err := context.New(
		context.WithOutboundDispatcher(frameworkOpts.outboundDispatcher),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithTransientStorageProvider(frameworkOpts.transientStoreProvider),
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
		context.WithPackager(frameworkOpts.packager),
		context.WithInboundTransportEndpoint(endPoint),
		context.WithVDRIRegistry(frameworkOpts.vdriRegistry),
	)

	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	for _, v := range frameworkOpts.protocolSvcCreators {
		svc, svcErr := v(ctx)
		if svcErr != nil {
			return fmt.Errorf("new protocol service failed: %w", svcErr)
		}

		frameworkOpts.services = append(frameworkOpts.services, svc)
		// after service was successfully created we need to add it to the context
		// since the introduce protocol depends on did-exchange
		if err := context.WithProtocolServices(frameworkOpts.services...)(ctx); err != nil {
			return err
		}
	}

	return nil
}

func createPackersAndPackager(frameworkOpts *Aries) error {
	ctx, err := context.New(
		context.WithKMS(frameworkOpts.kms),
		context.WithCrypto(frameworkOpts.crypto),
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
		context.WithStorageProvider(frameworkOpts.storeProvider), context.WithVDRIRegistry(frameworkOpts.vdriRegistry))
	if err != nil {
		return fmt.Errorf("create packager context failed: %w", err)
	}

	frameworkOpts.packager, err = frameworkOpts.packagerCreator(ctx)
	if err != nil {
		return fmt.Errorf("create packager failed: %w", err)
	}

	return nil
}
