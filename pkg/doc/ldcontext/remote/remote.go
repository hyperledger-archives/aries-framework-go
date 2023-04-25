/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package remote

import (
	"github.com/hyperledger/aries-framework-go/component/models/ld/context/remote"
)

// Provider is a remote JSON-LD context provider.
type Provider = remote.Provider

// NewProvider returns a new instance of the remote provider.
func NewProvider(endpoint string, opts ...ProviderOpt) *Provider {
	return remote.NewProvider(endpoint, opts...)
}

// Response represents a response from the remote source with JSON-LD context documents.
type Response = remote.Response

// ProviderOpt configures the remote context provider.
type ProviderOpt = remote.ProviderOpt

// HTTPClient represents an HTTP client.
type HTTPClient = remote.HTTPClient

// WithHTTPClient configures an HTTP client.
func WithHTTPClient(client HTTPClient) ProviderOpt {
	return remote.WithHTTPClient(client)
}
