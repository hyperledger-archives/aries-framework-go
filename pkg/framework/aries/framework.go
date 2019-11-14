/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/peer"
)

// Aries provides access to the context being managed by the framework. The context can be used to create aries clients.
type Aries struct {
	storeProvider             storage.Provider
	transientStoreProvider    storage.Provider
	protocolSvcCreators       []api.ProtocolSvcCreator
	services                  []dispatcher.Service
	outboundTransport         transport.OutboundTransport
	inboundTransport          transport.InboundTransport
	kmsCreator                api.KMSCreator
	kms                       api.CloseableKMS
	outboundDispatcherCreator dispatcher.OutboundCreator
	outboundDispatcher        dispatcher.Outbound
	packagerCreator           packager.Creator
	packager                  commontransport.Packager
	packerCreator             packer.Creator
	packerCreators            []packer.Creator
	primaryPacker             packer.Packer
	packers                   []packer.Packer
	vdriRegistry              vdriapi.Registry
	vdri                      []vdriapi.VDRI
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

	// Order of initializing service is important

	// Create kms
	if e := createKMS(frameworkOpts); e != nil {
		return nil, e
	}

	// Create vdri
	if e := createVDRI(frameworkOpts); e != nil {
		return nil, e
	}

	// create packers and packager (must be done after KMS)
	err = createPackersAndPackager(frameworkOpts)
	if err != nil {
		return nil, err
	}

	// Create outbound dispatcher
	err = createOutboundDispatcher(frameworkOpts)
	if err != nil {
		return nil, err
	}

	// Load services
	err = loadServices(frameworkOpts)
	if err != nil {
		return nil, err
	}

	// Start inbound transport
	err = startInboundTransport(frameworkOpts)
	if err != nil {
		return nil, err
	}

	return frameworkOpts, nil
}

// WithOutboundTransport injects an outbound transport to the Aries framework.
func WithOutboundTransport(outboundTransport transport.OutboundTransport) Option {
	return func(opts *Aries) error {
		opts.outboundTransport = outboundTransport
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

// WithOutboundDispatcher injects an outbound dispatcher service to the Aries framework.
func WithOutboundDispatcher(o dispatcher.OutboundCreator) Option {
	return func(opts *Aries) error {
		opts.outboundDispatcherCreator = o
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
	return context.New(
		context.WithOutboundDispatcher(a.outboundDispatcher),
		context.WithOutboundTransport(a.outboundTransport),
		context.WithProtocolServices(a.services...),
		context.WithKMS(a.kms),
		context.WithInboundTransportEndpoint(a.inboundTransport.Endpoint()),
		context.WithStorageProvider(a.storeProvider),
		context.WithTransientStorageProvider(a.transientStoreProvider),
		context.WithPacker(a.primaryPacker, a.packers...),
		context.WithPackager(a.packager),
		context.WithVDRIRegistry(a.vdriRegistry),
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

	return nil
}

func createKMS(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()),
		context.WithStorageProvider(frameworkOpts.storeProvider))
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
	ctx, err := context.New(context.WithKMS(frameworkOpts.kms),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()))
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	var opts []vdri.Option
	for _, v := range frameworkOpts.vdri {
		opts = append(opts, vdri.WithVDRI(v))
	}

	p, err := peer.New(ctx.StorageProvider(), peer.WithCreatorServiceType("did-communication"),
		peer.WithCreatorServiceEndpoint(ctx.InboundTransportEndpoint()))
	if err != nil {
		return fmt.Errorf("create new vdri peer failed: %w", err)
	}

	opts = append(opts, vdri.WithVDRI(p))

	frameworkOpts.vdriRegistry = vdri.New(ctx, opts...)

	return nil
}

func createOutboundDispatcher(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithKMS(frameworkOpts.kms),
		context.WithOutboundTransport(frameworkOpts.outboundTransport),
		context.WithPackager(frameworkOpts.packager))
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}

	frameworkOpts.outboundDispatcher, err = frameworkOpts.outboundDispatcherCreator(ctx)
	if err != nil {
		return fmt.Errorf("create outbound dispatcher failed: %w", err)
	}

	return nil
}

func startInboundTransport(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithKMS(frameworkOpts.kms),
		context.WithPackager(frameworkOpts.packager),
		context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()),
		context.WithProtocolServices(frameworkOpts.services...))
	if err != nil {
		return fmt.Errorf("context creation failed: %w", err)
	}
	// Start the inbound transport
	if err = frameworkOpts.inboundTransport.Start(ctx); err != nil {
		return fmt.Errorf("inbound transport start failed: %w", err)
	}

	return nil
}

func loadServices(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithOutboundDispatcher(frameworkOpts.outboundDispatcher),
		context.WithStorageProvider(frameworkOpts.storeProvider),
		context.WithTransientStorageProvider(frameworkOpts.transientStoreProvider),
		context.WithKMS(frameworkOpts.kms),
		context.WithPackager(frameworkOpts.packager),
		context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()),
		context.WithVDRIRegistry(frameworkOpts.vdriRegistry))

	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}

	for _, v := range frameworkOpts.protocolSvcCreators {
		svc, svcErr := v(ctx)
		if svcErr != nil {
			return fmt.Errorf("new protocol service failed: %w", svcErr)
		}

		frameworkOpts.services = append(frameworkOpts.services, svc)
	}

	return nil
}

func createPackersAndPackager(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithKMS(frameworkOpts.kms))
	if err != nil {
		return fmt.Errorf("create envelope context failed: %w", err)
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

	ctx, err = context.New(
		context.WithPacker(frameworkOpts.primaryPacker, frameworkOpts.packers...))
	if err != nil {
		return fmt.Errorf("create packager context failed: %w", err)
	}

	frameworkOpts.packager, err = frameworkOpts.packagerCreator(ctx)
	if err != nil {
		return fmt.Errorf("create packager failed: %w", err)
	}

	return nil
}
