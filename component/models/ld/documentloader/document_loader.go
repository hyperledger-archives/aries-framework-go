/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package documentloader

import (
	"errors"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/context/embed"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ErrContextNotFound is returned when JSON-LD context document is not found in the underlying storage.
var ErrContextNotFound = errors.New("context not found")

// provider contains dependencies for the JSON-LD document loader.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// DocumentLoader is an implementation of ld.DocumentLoader backed by storage.
type DocumentLoader struct {
	store                ldstore.ContextStore
	remoteDocumentLoader jsonld.DocumentLoader
}

// NewDocumentLoader returns a new DocumentLoader instance.
//
// Embedded contexts (`ldcontext/embed/third_party`) are preloaded into the underlying storage.
// Additional contexts can be set using WithExtraContexts() option or provided by one or more remote providers.
// Use multiple WithRemoteProvider() options for setting up more than one remote JSON-LD context provider.
//
// By default, missing contexts are not fetched from the remote URL. Use WithRemoteDocumentLoader() option
// to specify a custom loader that can resolve context documents from the network.
func NewDocumentLoader(ctx provider, opts ...Opts) (*DocumentLoader, error) {
	loaderOpts := &documentLoaderOpts{}

	for i := range opts {
		opts[i](loaderOpts)
	}

	contexts, err := prepareContexts(ctx.JSONLDRemoteProviderStore(), loaderOpts)
	if err != nil {
		return nil, fmt.Errorf("get contexts: %w", err)
	}

	store := ctx.JSONLDContextStore()

	if err = store.Import(contexts); err != nil {
		return nil, fmt.Errorf("import contexts: %w", err)
	}

	return &DocumentLoader{
		store:                store,
		remoteDocumentLoader: loaderOpts.remoteDocumentLoader,
	}, nil
}

func prepareContexts(
	providerStore ldstore.RemoteProviderStore,
	opts *documentLoaderOpts,
) ([]ldcontext.Document, error) {
	m := make(map[string]ldcontext.Document)

	for _, c := range append(embed.Contexts, opts.extraContexts...) {
		m[c.URL] = c
	}

	for _, p := range opts.remoteProviders {
		contexts, err := p.Contexts()
		if err != nil {
			return nil, fmt.Errorf("get provider contexts: %w", err)
		}

		for _, c := range contexts {
			m[c.URL] = c
		}

		if _, err = providerStore.Save(p.Endpoint()); err != nil {
			return nil, fmt.Errorf("save remote provider: %w", err)
		}
	}

	var contexts []ldcontext.Document

	for _, c := range m {
		contexts = append(contexts, c)
	}

	return contexts, nil
}

// LoadDocument resolves JSON-LD context document by document URL (u) either from storage or from remote URL.
// If document is not found in the storage and remote DocumentLoader is not specified, ErrContextNotFound is returned.
func (l *DocumentLoader) LoadDocument(u string) (*jsonld.RemoteDocument, error) {
	rd, err := l.store.Get(u)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("load document: %w", err)
		}

		if l.remoteDocumentLoader == nil { // fetching from the remote URL is disabled
			return nil, ErrContextNotFound
		}

		return l.loadDocumentFromURL(u)
	}

	return rd, nil
}

func (l *DocumentLoader) loadDocumentFromURL(u string) (*jsonld.RemoteDocument, error) {
	rd, err := l.remoteDocumentLoader.LoadDocument(u)
	if err != nil {
		return nil, fmt.Errorf("load remote context document: %w", err)
	}

	if err = l.store.Put(u, rd); err != nil {
		return nil, fmt.Errorf("save loaded document: %w", err)
	}

	return rd, nil
}

type documentLoaderOpts struct {
	remoteDocumentLoader jsonld.DocumentLoader
	extraContexts        []ldcontext.Document
	remoteProviders      []RemoteProvider
}

// Opts configures DocumentLoader during creation.
type Opts func(opts *documentLoaderOpts)

// WithRemoteDocumentLoader specifies loader for fetching JSON-LD context documents from remote URLs.
// Documents are fetched with this loader only if they are not found in the underlying storage.
func WithRemoteDocumentLoader(loader jsonld.DocumentLoader) Opts {
	return func(opts *documentLoaderOpts) {
		opts.remoteDocumentLoader = loader
	}
}

// WithExtraContexts sets the extra contexts (in addition to embedded) for preloading into the underlying storage.
func WithExtraContexts(contexts ...ldcontext.Document) Opts {
	return func(opts *documentLoaderOpts) {
		opts.extraContexts = contexts
	}
}

// RemoteProvider defines a remote JSON-LD context provider.
type RemoteProvider interface {
	Endpoint() string
	Contexts() ([]ldcontext.Document, error)
}

// WithRemoteProvider adds a remote JSON-LD context provider to the list of providers.
func WithRemoteProvider(provider RemoteProvider) Opts {
	return func(opts *documentLoaderOpts) {
		opts.remoteProviders = append(opts.remoteProviders, provider)
	}
}
