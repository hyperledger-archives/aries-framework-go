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
	errors "golang.org/x/xerrors"
)

// Provider supplies the framework configuration to client objects.
type Provider struct {
	outboundTransport   transport.OutboundTransport
	services            []dispatcher.Service
	protocolSvcCreators []api.ProtocolSvcCreator
	protocolConfig      api.ProtocolConfig
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

// InboundMessageHandler return inbound message handler
func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(payload []byte) error {
		// get the message type from the payload and dispatch based on the services
		msgType := &struct {
			Type string `json:"@type,omitempty"`
		}{}
		err := json.Unmarshal(payload, msgType)
		if err != nil {
			return errors.Errorf("invalid payload data format: %w", err)
		}

		// find the service which accepts the message type
		for _, svc := range p.services {
			if svc.Accept(msgType.Type) {
				return svc.Handle(dispatcher.DIDCommMsg{Type: msgType.Type, Payload: payload})
			}
		}
		return errors.New(fmt.Sprintf("no message handlers found for the message type: %s", msgType.Type))
	}
}

// ProtocolConfig returns protocol config
func (p *Provider) ProtocolConfig() api.ProtocolConfig {
	return p.protocolConfig
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

// WithProtocolConfig injects protocol config into the framework
func WithProtocolConfig(protocolConfig api.ProtocolConfig) ProviderOption {
	return func(opts *Provider) error {
		opts.protocolConfig = protocolConfig
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
