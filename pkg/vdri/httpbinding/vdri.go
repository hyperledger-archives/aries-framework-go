/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

var logger = log.New("aries-framework/vdri/httpbinding")

// VDRI via HTTP(s) endpoint.
type VDRI struct {
	endpointURL      string
	client           *http.Client
	accept           Accept
	resolveAuthToken string
}

// Accept is method to accept did method.
type Accept func(method string) bool

// New creates new DID Resolver.
func New(endpointURL string, opts ...Option) (*VDRI, error) {
	vdri := &VDRI{client: &http.Client{}, accept: func(method string) bool { return true }}

	for _, opt := range opts {
		opt(vdri)
	}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	vdri.endpointURL = endpointURL

	return vdri, nil
}

// Accept did method - attempt to resolve any method.
func (v *VDRI) Accept(method string) bool {
	return v.accept(method)
}

// Store did doc.
func (v *VDRI) Store(doc *did.Doc, by *[]vdriapi.ModifiedBy) error {
	logger.Warnf(" store not supported in http binding vdri")
	return nil
}

// Build did doc.
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	return nil, fmt.Errorf("build not supported in http binding vdri")
}

// Close frees resources being maintained by vdri.
func (v *VDRI) Close() error {
	return nil
}

// Option configures the peer vdri.
type Option func(opts *VDRI)

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver.
func WithTimeout(timeout time.Duration) Option {
	return func(opts *VDRI) {
		opts.client.Timeout = timeout
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDRI) {
		opts.client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
}

// WithAccept option is for accept did method.
func WithAccept(accept Accept) Option {
	return func(opts *VDRI) {
		opts.accept = accept
	}
}

// WithResolveAuthToken add auth token for resolve.
func WithResolveAuthToken(authToken string) Option {
	return func(opts *VDRI) {
		opts.resolveAuthToken = "Bearer " + authToken
	}
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
