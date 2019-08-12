/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// ProviderFactory represents the default transport provider factory.
type ProviderFactory struct {
}

// NewProviderFactory returns the default transport provider factory.
func NewProviderFactory() *ProviderFactory {
	f := ProviderFactory{}
	return &f
}

// CreateOutboundTransport returns a new default implementation of outbound transport provider
func (f *ProviderFactory) CreateOutboundTransport() transport.OutboundTransport {
	// TODO - https://github.com/hyperledger/aries-framework-go/issues/83
	return nil
}
