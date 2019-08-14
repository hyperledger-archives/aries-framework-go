/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	errors "golang.org/x/xerrors"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundTransport transport.OutboundTransport
}

// New instantiated new context provider
func New(opts ...ProviderOption) (*Provider, error) {
	ctxProvider := Provider{}
	for _, opt := range opts {
		err := opt(&ctxProvider)
		if err != nil {
			return nil, errors.Errorf("Error in option passed to New: %w", err)
		}
	}
	return &ctxProvider, nil
}

// OutboundTransport returns the outbound transport provider
func (p *Provider) OutboundTransport() transport.OutboundTransport {
	return p.outboundTransport
}

// ProviderOption configures the framework.
type ProviderOption func(opts *Provider) error

// WithOutboundTransport injects transport provider into the framework
func WithOutboundTransport(ot transport.OutboundTransport) ProviderOption {
	return func(opts *Provider) error {
		opts.outboundTransport = ot
		return nil
	}
}
