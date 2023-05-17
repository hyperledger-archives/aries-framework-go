/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/component/vdr/httpbinding"
)

const (
	// VersionIDOpt version id opt this option is not mandatory.
	VersionIDOpt = httpbinding.VersionIDOpt
	// VersionTimeOpt version time opt this option is not mandatory.
	VersionTimeOpt = httpbinding.VersionTimeOpt
)

type authTokenProvider interface {
	AuthToken() (string, error)
}

// VDR via HTTP(s) endpoint.
type VDR = httpbinding.VDR

// Accept is method to accept did method.
type Accept = httpbinding.Accept

// New creates new DID Resolver.
func New(endpointURL string, opts ...Option) (*VDR, error) {
	return httpbinding.New(endpointURL, opts...)
}

// Option configures the peer vdr.
type Option = httpbinding.Option

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver.
func WithTimeout(timeout time.Duration) Option {
	return httpbinding.WithTimeout(timeout)
}

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return httpbinding.WithHTTPClient(httpClient)
}

// WithAccept option is for accept did method.
func WithAccept(accept Accept) Option {
	return httpbinding.WithAccept(accept)
}

// WithResolveAuthToken add auth token for resolve.
func WithResolveAuthToken(authToken string) Option {
	return httpbinding.WithResolveAuthToken(authToken)
}

// WithResolveAuthTokenProvider add auth token provider.
func WithResolveAuthTokenProvider(p authTokenProvider) Option {
	return httpbinding.WithResolveAuthTokenProvider(p)
}
