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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

var logger = log.New("aries-framework/vdr/httpbinding")

// VDR via HTTP(s) endpoint.
type VDR struct {
	endpointURL      string
	client           *http.Client
	accept           Accept
	resolveAuthToken string
}

// Accept is method to accept did method.
type Accept func(method string) bool

// New creates new DID Resolver.
func New(endpointURL string, opts ...Option) (*VDR, error) {
	v := &VDR{client: &http.Client{}, accept: func(method string) bool { return true }}

	for _, opt := range opts {
		opt(v)
	}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	v.endpointURL = endpointURL

	return v, nil
}

// Accept did method - attempt to resolve any method.
func (v *VDR) Accept(method string) bool {
	return v.accept(method)
}

// Store did doc.
func (v *VDR) Store(doc *did.Doc, by *[]vdrdoc.ModifiedBy) error {
	logger.Warnf(" store not supported in http binding vdr")
	return nil
}

// Build did doc.
func (v *VDR) Build(keyManager kms.KeyManager, opts ...create.Option) (*did.DocResolution, error) {
	return nil, fmt.Errorf("build not supported in http binding vdr")
}

// Close frees resources being maintained by vdr.
func (v *VDR) Close() error {
	return nil
}

// Update DID Document.
func (v *VDR) Update(didID string, opts ...update.Option) error {
	return fmt.Errorf("update not supported")
}

// Recover DID Document.
func (v *VDR) Recover(didID string, opts ...recovery.Option) error {
	return fmt.Errorf("recover not supported")
}

// Deactivate DID Document.
func (v *VDR) Deactivate(didID string, opts ...deactivate.Option) error {
	return fmt.Errorf("deactivate not supported")
}

// Option configures the peer vdr.
type Option func(opts *VDR)

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver.
func WithTimeout(timeout time.Duration) Option {
	return func(opts *VDR) {
		opts.client.Timeout = timeout
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDR) {
		opts.client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
}

// WithAccept option is for accept did method.
func WithAccept(accept Accept) Option {
	return func(opts *VDR) {
		opts.accept = accept
	}
}

// WithResolveAuthToken add auth token for resolve.
func WithResolveAuthToken(authToken string) Option {
	return func(opts *VDR) {
		opts.resolveAuthToken = "Bearer " + authToken
	}
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
