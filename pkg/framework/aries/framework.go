/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Aries provides access to clients being managed by the framework.
type Aries struct {
	transport                 api.TransportProviderFactory
	storeProvider             storage.Provider
	protocolSvcCreators       []api.ProtocolSvcCreator
	services                  []dispatcher.Service
	inboundTransport          transport.InboundTransport
	walletCreator             api.WalletCreator
	wallet                    api.CloseableWallet
	outboundDispatcherCreator dispatcher.OutboundCreator
	outboundDispatcher        dispatcher.Outbound
	packagerCreator           envelope.PackagerCreator
	packager                  envelope.Packager
	crypterCreator            crypto.CrypterCreator
	crypter                   crypto.Crypter
	didResolver               didresolver.Resolver
	// TODO: the DID provider options should be part of a verifiable data registry (vdr) option.
	didStore didstore.Storage
}

// Option configures the framework.
type Option func(opts *Aries) error

// New initializes the Aries framework based on the set of options provided.
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
	//  This needs to be resolved and should define a clear relationship between these.

	// Order of initializing service is important

	// Create wallet
	if e := createWallet(frameworkOpts); e != nil {
		return nil, e
	}

	// create create crypter and packager (must be done after Wallet)
	err = createCrypterAndPackager(frameworkOpts)
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

// WithTransportProviderFactory injects a protocol provider factory interface to Aries
func WithTransportProviderFactory(transportProv api.TransportProviderFactory) Option {
	return func(opts *Aries) error {
		opts.transport = transportProv
		return nil
	}
}

// WithInboundTransport injects a inbound transport to the Aries framework
func WithInboundTransport(inboundTransport transport.InboundTransport) Option {
	return func(opts *Aries) error {
		opts.inboundTransport = inboundTransport
		return nil
	}
}

// WithDIDResolver injects a DID resolver to the Aries framework
func WithDIDResolver(didResolver didresolver.Resolver) Option {
	return func(opts *Aries) error {
		opts.didResolver = didResolver
		return nil
	}
}

// WithStoreProvider injects a storage provider to the Aries framework
func WithStoreProvider(prov storage.Provider) Option {
	return func(opts *Aries) error {
		opts.storeProvider = prov
		return nil
	}
}

// WithProtocols injects a protocol service to the Aries framework
func WithProtocols(protocolSvcCreator ...api.ProtocolSvcCreator) Option {
	return func(opts *Aries) error {
		opts.protocolSvcCreators = append(opts.protocolSvcCreators, protocolSvcCreator...)
		return nil
	}
}

// WithOutboundDispatcher injects a outbound dispatcher service to the Aries framework
func WithOutboundDispatcher(o dispatcher.OutboundCreator) Option {
	return func(opts *Aries) error {
		opts.outboundDispatcherCreator = o
		return nil
	}
}

// WithWallet injects a wallet service to the Aries framework
func WithWallet(w api.WalletCreator) Option {
	return func(opts *Aries) error {
		opts.walletCreator = w
		return nil
	}
}

// WithCrypter injects a crypter service to the Aries framework
func WithCrypter(c crypto.CrypterCreator) Option {
	return func(opts *Aries) error {
		opts.crypterCreator = c
		return nil
	}
}

// WithPackager injects a WithPackager service to the Aries framework
func WithPackager(p envelope.PackagerCreator) Option {
	return func(opts *Aries) error {
		opts.packagerCreator = p
		return nil
	}
}

// WithDIDStore injects a did store to the Aries framework
func WithDIDStore(didStore didstore.Storage) Option {
	return func(opts *Aries) error {
		opts.didStore = didStore
		return nil
	}
}

// DIDResolver returns the framework configured DID Resolver.
func (a *Aries) DIDResolver() didresolver.Resolver {
	return a.didResolver
}

// Context provides handle to framework context
func (a *Aries) Context() (*context.Provider, error) {
	ot, err := a.transport.CreateOutboundTransport()
	if err != nil {
		return nil, fmt.Errorf("outbound transport initialization failed: %w", err)
	}
	return context.New(
		context.WithOutboundDispatcher(a.outboundDispatcher),
		context.WithOutboundTransport(ot), context.WithProtocolServices(a.services...),
		// TODO configure inbound external endpoints
		context.WithWallet(a.wallet), context.WithInboundTransportEndpoint(a.inboundTransport.Endpoint()),
		context.WithStorageProvider(a.storeProvider),
		context.WithCrypter(a.crypter),
		context.WithPackager(a.packager),
		context.WithDIDResolver(a.didResolver),
		context.WithDIDStore(a.didStore),
	)
}

// Close frees resources being maintained by the framework.
func (a *Aries) Close() error {
	if a.wallet != nil {
		err := a.wallet.Close()
		if err != nil {
			return fmt.Errorf("failed to close the wallet: %w", err)
		}
	}
	if a.storeProvider != nil {
		err := a.storeProvider.Close()
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

func createWallet(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()),
		context.WithStorageProvider(frameworkOpts.storeProvider))
	if err != nil {
		return fmt.Errorf("create context failed: %w", err)
	}
	frameworkOpts.wallet, err = frameworkOpts.walletCreator(ctx)
	if err != nil {
		return fmt.Errorf("create wallet failed: %w", err)
	}
	return nil
}

func createOutboundDispatcher(frameworkOpts *Aries) error {
	ot, err := frameworkOpts.transport.CreateOutboundTransport()
	if err != nil {
		return fmt.Errorf("outbound transport initialization failed: %w", err)
	}
	ctx, err := context.New(context.WithWallet(frameworkOpts.wallet),
		context.WithOutboundTransport(ot),
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
	ctx, err := context.New(context.WithWallet(frameworkOpts.wallet),
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
		context.WithWallet(frameworkOpts.wallet),
		context.WithPackager(frameworkOpts.packager),
		context.WithDIDResolver(frameworkOpts.didResolver),
		context.WithInboundTransportEndpoint(frameworkOpts.inboundTransport.Endpoint()))
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

func createCrypterAndPackager(frameworkOpts *Aries) error {
	ctx, err := context.New(context.WithWallet(frameworkOpts.wallet))
	if err != nil {
		return fmt.Errorf("create crypter context failed: %w", err)
	}

	frameworkOpts.crypter, err = frameworkOpts.crypterCreator(ctx)
	if err != nil {
		return fmt.Errorf("create crypter failed: %w", err)
	}

	ctx, err = context.New(context.WithCrypter(frameworkOpts.crypter))
	if err != nil {
		return fmt.Errorf("create packager context failed: %w", err)
	}

	frameworkOpts.packager, err = frameworkOpts.packagerCreator(ctx)
	if err != nil {
		return fmt.Errorf("create packager failed: %w", err)
	}
	return nil
}
