/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	jsonld "github.com/piprate/json-gold/ld"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/documentloader"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
)

// ErrContextNotFound is returned when JSON-LD context document is not found in the underlying storage.
var ErrContextNotFound = documentloader.ErrContextNotFound

// provider contains dependencies for the JSON-LD document loader.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// DocumentLoader is an implementation of ld.DocumentLoader backed by storage.
type DocumentLoader = documentloader.DocumentLoader

// NewDocumentLoader returns a new DocumentLoader instance.
//
// Embedded contexts (`ldcontext/embed/third_party`) are preloaded into the underlying storage.
// Additional contexts can be set using WithExtraContexts() option or provided by one or more remote providers.
// Use multiple WithRemoteProvider() options for setting up more than one remote JSON-LD context provider.
//
// By default, missing contexts are not fetched from the remote URL. Use WithRemoteDocumentLoader() option
// to specify a custom loader that can resolve context documents from the network.
func NewDocumentLoader(ctx provider, opts ...DocumentLoaderOpts) (*DocumentLoader, error) {
	return documentloader.NewDocumentLoader(ctx, opts...)
}

// DocumentLoaderOpts configures DocumentLoader during creation.
type DocumentLoaderOpts = documentloader.Opts

// WithRemoteDocumentLoader specifies loader for fetching JSON-LD context documents from remote URLs.
// Documents are fetched with this loader only if they are not found in the underlying storage.
func WithRemoteDocumentLoader(loader jsonld.DocumentLoader) DocumentLoaderOpts {
	return documentloader.WithRemoteDocumentLoader(loader)
}

// WithExtraContexts sets the extra contexts (in addition to embedded) for preloading into the underlying storage.
func WithExtraContexts(contexts ...ldcontext.Document) DocumentLoaderOpts {
	return documentloader.WithExtraContexts(contexts...)
}

// RemoteProvider defines a remote JSON-LD context provider.
type RemoteProvider = documentloader.RemoteProvider

// WithRemoteProvider adds a remote JSON-LD context provider to the list of providers.
func WithRemoteProvider(provider RemoteProvider) DocumentLoaderOpts {
	return documentloader.WithRemoteProvider(provider)
}
