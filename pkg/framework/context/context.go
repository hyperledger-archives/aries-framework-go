/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	exchangeService "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/exchange/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	errors "golang.org/x/xerrors"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundTransport transport.OutboundTransport
	apiHandlers       []api.Handler
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

	//Load services and initialize context with API handlers
	exchangeSvc := exchangeService.New(&ctxProvider)
	ctxProvider.apiHandlers = append(ctxProvider.apiHandlers, exchangeSvc.GetAPIHandlers()...)

	return &ctxProvider, nil
}

// OutboundTransport returns the outbound transport provider
func (p *Provider) OutboundTransport() transport.OutboundTransport {
	return p.outboundTransport
}

// RESTHandlers returns the REST API handlers for controller endpoints
func (p *Provider) RESTHandlers() []api.Handler {
	return p.apiHandlers
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
