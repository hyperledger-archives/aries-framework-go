/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	"net/http"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/didconfig/client"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// Client is a JSON-LD SDK client.
type Client = client.Client

// New creates new did configuration client.
func New(opts ...Option) *Client {
	return client.New(opts...)
}

// HTTPClient represents an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Option configures the did configuration client.
type Option = client.Option

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient HTTPClient) Option {
	return client.WithHTTPClient(httpClient)
}

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) Option {
	return client.WithJSONLDDocumentLoader(documentLoader)
}

type didResolver interface {
	Resolve(did string, opts ...vdrspi.DIDMethodOption) (*did.DocResolution, error)
}

// WithVDRegistry defines a vdr service.
func WithVDRegistry(didResolver didResolver) Option {
	return client.WithVDRegistry(didResolver)
}
