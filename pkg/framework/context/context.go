/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	errors "golang.org/x/xerrors"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundTransport   transport.OutboundTransport
	services            []dispatcher.Service
	protocolSvcCreators []api.ProtocolSvcCreator
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

	//Load services
	for _, v := range ctxProvider.protocolSvcCreators {
		svc, err := v(&ctxProvider)
		if err != nil {
			return nil, errors.Errorf("new protocol service failed: %w", err)
		}
		ctxProvider.services = append(ctxProvider.services, svc)
	}
	return &ctxProvider, nil
}

// OutboundTransport returns the outbound transport provider
func (p *Provider) OutboundTransport() transport.OutboundTransport {
	return p.outboundTransport
}

// Service return protocol service
func (p *Provider) Service(id string) (interface{}, error) {
	for _, v := range p.services {
		if v.Name() == id {
			return v, nil
		}
	}
	return nil, api.SvcErrNotFound
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

// WithProtocols injects protocol svc into context
func WithProtocols(protocolSvcCreator ...api.ProtocolSvcCreator) ProviderOption {
	return func(opts *Provider) error {
		opts.protocolSvcCreators = protocolSvcCreator
		return nil
	}
}
