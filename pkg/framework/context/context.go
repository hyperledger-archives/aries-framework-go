/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundTransport transport.OutboundTransport
	services          []dispatcher.Service
}

// New instantiated new context provider
func New(opts ...ProviderOption) (*Provider, error) {
	ctxProvider := Provider{}
	for _, opt := range opts {
		err := opt(&ctxProvider)
		if err != nil {
			return nil, fmt.Errorf("option failed: %w", err)
		}
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
	return nil, api.ErrSvcNotFound
}

// InboundMessageHandler return inbound message handler
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(payload []byte) error {
		// get the message type from the payload and dispatch based on the services
		msgType := &struct {
			Type string `json:"@type,omitempty"`
		}{}
		err := json.Unmarshal(payload, msgType)
		if err != nil {
			return fmt.Errorf("invalid payload data format: %w", err)
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msgType.Type) {
				return svc.Handle(dispatcher.DIDCommMsg{Type: msgType.Type, Payload: payload})
			}
		}
		return fmt.Errorf("no message handlers found for the message type: %s", msgType.Type)
	}
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

// WithProtocolServices injects protocol services into the context.
func WithProtocolServices(services ...dispatcher.Service) ProviderOption {
	return func(opts *Provider) error {
		opts.services = services
		return nil
	}
}
