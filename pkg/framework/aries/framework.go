/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// DIDResolver interface for DID resolver.
type DIDResolver interface {
	Resolve(did string, opts ...didresolver.ResolveOpt) (*did.Doc, error)
}

// Aries provides access to clients being managed by the framework.
type Aries struct {
	transport           api.TransportProviderFactory
	didResolver         DIDResolver
	storeProvider       storage.Provider
	protocolSvcCreators []api.ProtocolSvcCreator
	services            []dispatcher.Service
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
			return nil, fmt.Errorf("close err: %s Error in option passed to New: %w", closeErr, err)
		}
	}

	// get the default framework options
	err := defFrameworkOpts(frameworkOpts)
	if err != nil {
		return nil, fmt.Errorf("default option initialization failed: %w", err)
	}

	ctxProvider, err := frameworkOpts.Context()
	if err != nil {
		return nil, fmt.Errorf("context creation failed: %w", err)
	}

	//Load services
	for _, v := range frameworkOpts.protocolSvcCreators {
		svc, err := v(ctxProvider)
		if err != nil {
			return nil, fmt.Errorf("new protocol service failed: %w", err)
		}
		frameworkOpts.services = append(frameworkOpts.services, svc)
	}

	return frameworkOpts, nil
}

// WithTransportProviderFactory injects a protocol provider factory interface to Aries
func WithTransportProviderFactory(transport api.TransportProviderFactory) Option {
	return func(opts *Aries) error {
		opts.transport = transport
		return nil
	}
}

// WithDIDResolver injects a DID resolver to the Aries framework
func WithDIDResolver(didResolver DIDResolver) Option {
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

// DIDResolver returns the framework configured DID Resolver.
func (a *Aries) DIDResolver() DIDResolver {
	return a.didResolver
}

// Context provides handle to framework context
func (a *Aries) Context() (*context.Provider, error) {
	ot, err := a.transport.CreateOutboundTransport()
	if err != nil {
		return nil, fmt.Errorf("outbound transport initialization failed: %w", err)
	}

	return context.New(
		context.WithOutboundTransport(ot), context.WithProtocolServices(a.services...),
	)
}

// Close frees resources being maintained by the framework.
func (a *Aries) Close() error {
	if a.storeProvider != nil {
		err := a.storeProvider.Close()
		if err != nil {
			return fmt.Errorf("failed to close the framework: %w", err)
		}
	}
	return nil
}
