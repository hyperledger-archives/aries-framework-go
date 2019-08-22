/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpbinding

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	errors "golang.org/x/xerrors"
)

var logger = log.New("aries-framework/didmethod/httpbinding")

// resolverOpts holds options for the DID Resolver
// it has a http.Client instance initialized with default parameters
type resolverOpts struct {
	client *http.Client
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

// resolveDID makes DID resolution via HTTP
func (res *DIDResolver) resolveDID(url string) ([]byte, error) {
	resp, err := res.client.Get(url)
	if err != nil {
		return nil, errors.Errorf("HTTP Get request failed: %w", err)
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
			return nil, errors.Errorf("Failed to read response body: %w", err)
		}

		return gotBody, nil

	} else if notExistentDID(resp) {
		return nil, errors.Errorf("Input DID does not exist: %w", err)
	}

	return nil, errors.Errorf("Unsupported response from DID Resolver with status code: %v", resp.StatusCode)
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
		return nil, errors.Errorf("Invalid base url: %w", err)
	}

	return &DIDResolver{
		endpointURL: endpointURL,
		client:      clOpts.client,
	}, nil
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (res *DIDResolver) Read(DID string, _ ...didresolver.ResolveOpt) ([]byte, error) {
	reqURL, _ := url.ParseRequestURI(res.endpointURL)

	reqURL.Path = path.Join(reqURL.Path, DID)

	return res.resolveDID(reqURL.String())
}

// Accept did method - attempt to resolve any method
func (res *DIDResolver) Accept(method string) bool {
	return true
}

// DIDResolver DID Resolver via HTTP(s) endpoint
type DIDResolver struct {
	endpointURL string
	client      *http.Client
}
