/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/didconfig"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

var logger = log.New("aries-framework/client/did-config")

const defaultTimeout = time.Minute

// Client is a JSON-LD SDK client.
type Client struct {
	httpClient    HTTPClient
	didConfigOpts []didconfig.DIDConfigurationOpt
}

// New creates new did configuration client.
func New(opts ...Option) *Client {
	client := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Option configures the did configuration client.
type Option func(opts *Client)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient HTTPClient) Option {
	return func(opts *Client) {
		opts.httpClient = httpClient
	}
}

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) Option {
	return func(opts *Client) {
		opts.didConfigOpts = append(opts.didConfigOpts, didconfig.WithJSONLDDocumentLoader(documentLoader))
	}
}

// WithVDRegistry defines a vdr service.
func WithVDRegistry(vdrRegistry vdrapi.Registry) Option {
	return func(opts *Client) {
		opts.didConfigOpts = append(opts.didConfigOpts, didconfig.WithVDRegistry(vdrRegistry))
	}
}

// VerifyDIDAndDomain will verify that there is valid domain linkage credential in did configuration
// for specified did and domain.
func (c *Client) VerifyDIDAndDomain(did, domain string) error {
	endpoint := domain + "/.well-known/did-configuration.json"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("new HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("httpClient.Do: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("endpoint %s returned status '%d' and message '%s'",
			endpoint, resp.StatusCode, responseBytes)
	}

	return didconfig.VerifyDIDAndDomain(responseBytes, did, domain)
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Warnf("failed to close response body: %v", e)
	}
}
