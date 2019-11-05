/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
)

var logger = log.New("aries-framework/didmethod/httpbinding")

// Accept is method to accept did method
type Accept func(method string) bool

// resolverOpts holds options for the DID Resolver
// it has a http.Client instance initialized with default parameters
type resolverOpts struct {
	client *http.Client
	accept Accept
}

// ResolverOpt is the DID Resolver option
type ResolverOpt func(opts *resolverOpts)

// WithTimeout option is for definition of HTTP(s) timeout value of DID Resolver
func WithTimeout(timeout time.Duration) ResolverOpt {
	return func(opts *resolverOpts) {
		opts.client.Timeout = timeout
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) ResolverOpt {
	return func(opts *resolverOpts) {
		opts.client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
}

// WithAccept option is for accept did method
func WithAccept(accept Accept) ResolverOpt {
	return func(opts *resolverOpts) {
		opts.accept = accept
	}
}

// resolveDID makes DID resolution via HTTP
func (res *DIDResolver) resolveDID(uri string) ([]byte, error) {
	resp, err := res.client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("HTTP Get request failed: %w", err)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("Failed to close response body: %v", e)
		}
	}()

	// TODO support for service endpoint URL resolution
	if containsDIDDocument(resp) {
		var gotBody []byte

		gotBody, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body failed: %w", err)
		}

		return gotBody, nil
	} else if notExistentDID(resp) {
		return nil, fmt.Errorf("DID does not exist for request: %s", uri)
	}

	return nil, fmt.Errorf("unsupported response from DID resolver [%v] header [%s]",
		resp.StatusCode, resp.Header.Get("Content-type"))
}

// notExistentDID checks if requested DID is not found on remote DID resolver
func notExistentDID(resp *http.Response) bool {
	return resp.StatusCode == http.StatusNotFound
}

// containsDIDDocument checks weather reply from remote DID resolver contains DID document
func containsDIDDocument(resp *http.Response) bool {
	return resp.StatusCode == http.StatusOK && resp.Header.Get("Content-type") == "application/did+ld+json"
}

// New creates new DID Resolver
func New(endpointURL string, opts ...ResolverOpt) (*DIDResolver, error) {
	// Apply options
	clOpts := &resolverOpts{client: &http.Client{}}

	for _, opt := range opts {
		opt(clOpts)
	}

	// Validate host
	_, err := url.ParseRequestURI(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("base URL invalid: %w", err)
	}

	if clOpts.accept == nil {
		clOpts.accept = func(method string) bool { return true }
	}

	return &DIDResolver{
		endpointURL: endpointURL,
		client:      clOpts.client,
		accept:      clOpts.accept,
	}, nil
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (res *DIDResolver) Read(did string, _ ...didresolver.ResolveOpt) ([]byte, error) {
	reqURL, err := url.ParseRequestURI(res.endpointURL)
	if err != nil {
		return nil, fmt.Errorf("url parse request uri failed: %w", err)
	}

	reqURL.Path = path.Join(reqURL.Path, did)

	return res.resolveDID(reqURL.String())
}

// Accept did method - attempt to resolve any method
func (res *DIDResolver) Accept(method string) bool {
	return res.accept(method)
}

// DIDResolver DID Resolver via HTTP(s) endpoint
type DIDResolver struct {
	endpointURL string
	client      *http.Client
	accept      Accept
}
