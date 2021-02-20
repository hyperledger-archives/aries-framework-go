/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package jsonld provides common framework JSON-LD utilities.
package jsonld

import (
	"fmt"
	"net/http"

	"github.com/piprate/json-gold/ld"
)

// NewCachingDocumentLoader creates a Document Loader with default framework options.
func NewCachingDocumentLoader() *ld.CachingDocumentLoader {
	return ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(httpclient()))
}

// NewCachingDocumentLoaderWithRemote creates a Document Loader with remote enabled.
// TODO: remove once framework is updated to preload context from stores.
func NewCachingDocumentLoaderWithRemote() *ld.CachingDocumentLoader {
	return ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))
}

type disabledNetworkTransport struct{}

func (*disabledNetworkTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("network is disabled [%s]", r.URL)
}

func httpclient() *http.Client {
	return &http.Client{
		Transport: &disabledNetworkTransport{},
	}
}
