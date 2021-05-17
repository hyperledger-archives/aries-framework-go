/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	cmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
	rest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
)

var logger = log.New("aries-framework/client/jsonld/context")

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client represents a REST client for managing JSON-LD contexts.
type Client struct {
	endpoint string
	http     HTTPClient
}

// NewClient returns a new JSON-LD context REST client.
func NewClient(endpoint string, opts ...Option) *Client {
	c := &Client{
		endpoint: endpoint,
		http:     http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Add adds JSON-LD context documents to the underlying storage.
func (c *Client) Add(ctx context.Context, docs ...jsonld.ContextDocument) error {
	r := cmd.AddRequest{Documents: docs}

	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal AddRequest: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+rest.AddContextPath, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("new http request: %w", err)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}

	defer func() {
		e := res.Body.Close()
		if e != nil {
			logger.Errorf("Failed to close response body: %s", e.Error())
		}
	}()

	if res.StatusCode != http.StatusOK {
		return getResponseError(res.Body)
	}

	return nil
}

func getResponseError(reader io.Reader) error {
	var errorResponse struct {
		Message string `json:"message"`
	}

	if err := json.NewDecoder(reader).Decode(&errorResponse); err != nil {
		return fmt.Errorf("decode error response: %w", err)
	}

	return errors.New(errorResponse.Message)
}

// Option configures the JSON-LD context client.
type Option func(opts *Client)

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(client HTTPClient) Option {
	return func(opts *Client) {
		opts.http = client
	}
}
