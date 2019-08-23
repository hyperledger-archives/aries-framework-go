/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	httptransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
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
func (f *ProviderFactory) CreateOutboundTransport() (transport.OutboundTransport, error) {
	return httptransport.NewOutbound(httptransport.WithOutboundHTTPClient(&http.Client{}))
}
