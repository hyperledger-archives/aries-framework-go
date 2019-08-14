/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	errors "golang.org/x/xerrors"
)

// Aries provides access to clients being managed by the framework.
type Aries struct {
	transport api.TransportProviderFactory
}

// Option configures the framework.
type Option func(opts *Aries) error

// New initializes the Aries framework based on the set of options provided.
func New(opts ...Option) (*Aries, error) {
	// get the default framework options
	defOpts := defFrameworkOpts()

	frameworkOpts := &Aries{}

	// generate framework configs from options
	for _, option := range append(defOpts, opts...) {
		err := option(frameworkOpts)
		if err != nil {
			return nil, errors.Errorf("Error in option passed to New: %w", err)
		}
	}

	return frameworkOpts, nil
}

// WithTransportProviderFactory injects a protocol provider factory interface to Aries
func WithTransportProviderFactory(ot api.TransportProviderFactory) Option {
	return func(opts *Aries) error {
		opts.transport = ot
		return nil
	}
}

// Context provides handle to framework context
func (a *Aries) Context() (*context.Provider, error) {
	return context.New(context.WithOutboundTransport(a.transport.CreateOutboundTransport()))
}
