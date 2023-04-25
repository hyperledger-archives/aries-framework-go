/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/component/log"
	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
)

const defaultTimeout = time.Minute

var logger = log.New("aries-framework/ldcontext/remote")

// Provider is a remote JSON-LD context provider.
type Provider struct {
	endpoint   string
	httpClient HTTPClient
}

// NewProvider returns a new instance of the remote provider.
func NewProvider(endpoint string, opts ...ProviderOpt) *Provider {
	provider := &Provider{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}

	for _, opt := range opts {
		opt(provider)
	}

	return provider
}

// Response represents a response from the remote source with JSON-LD context documents.
type Response struct {
	Documents []ldcontext.Document `json:"documents"`
}

// Endpoint returns endpoint of the remote JSON-LD context source.
func (p *Provider) Endpoint() string {
	return p.endpoint
}

// Contexts returns JSON-LD contexts from the remote source.
func (p *Provider) Contexts() ([]ldcontext.Document, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpClient do: %w", err)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("Failed to close response body: %s", e.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response status code: %d", resp.StatusCode)
	}

	var response Response

	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return response.Documents, nil
}

// ProviderOpt configures the remote context provider.
type ProviderOpt func(*Provider)

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient configures an HTTP client.
func WithHTTPClient(client HTTPClient) ProviderOpt {
	return func(p *Provider) {
		p.httpClient = client
	}
}
