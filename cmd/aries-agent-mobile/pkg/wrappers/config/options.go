/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"

// Options represents configurations for Aries.
type Options struct {
	UseLocalAgent bool

	AgentURL string
	APIToken string

	Label                string
	AutoAccept           bool
	TransportReturnRoute string
	LogLevel             string
	DBNamespace          string

	// expected to be ignored by gomobile
	// not intended to be used by golang code
	HTTPResolvers     []string
	OutboundTransport []string

	Notifier api.Notifier
}

// New returns an instance of Options which can be used to configure an aries controller instance.
func New() *Options {
	return &Options{}
}

// AddHTTPResolver appends an http resolver url to the options.
func (o *Options) AddHTTPResolver(resolverURL string) {
	o.HTTPResolvers = append(o.HTTPResolvers, resolverURL)
}

// AddOutboundTransport appends a transport type to the options e.g. http or ws.
func (o *Options) AddOutboundTransport(transportType string) {
	o.OutboundTransport = append(o.OutboundTransport, transportType)
}
