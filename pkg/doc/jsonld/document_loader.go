/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ContextsDBName is a name of DB for storing JSON-LD contexts.
const ContextsDBName = "jsonldContexts"

// ErrContextNotFound is returned when JSON-LD context document is not found in the underlying storage.
var ErrContextNotFound = errors.New("context document not found")

// DocumentLoader is an implementation of ld.DocumentLoader backed by storage.
type DocumentLoader struct {
	store                storage.Store
	remoteDocumentLoader ld.DocumentLoader
}

// NewDocumentLoader returns a new DocumentLoader instance.
//
// Embedded contexts (`contexts/third_party`) are always preloaded into the underlying storage.
// Additional contexts can be set using WithExtraContexts() option.
//
// By default, missing contexts are not fetched from the remote URL. Use WithRemoteDocumentLoader() option
// to specify a custom loader that can resolve context documents from the network.
func NewDocumentLoader(storageProvider storage.Provider, opts ...DocumentLoaderOpts) (*DocumentLoader, error) {
	options := &documentLoaderOpts{}

	for i := range opts {
		opts[i](options)
	}

	store, err := storageProvider.OpenStore(ContextsDBName)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	contexts := append(embedContexts, options.extraContexts...)

	// preload context documents into the underlying storage
	if err = save(store, contexts); err != nil {
		return nil, fmt.Errorf("save context documents: %w", err)
	}

	return &DocumentLoader{
		store:                store,
		remoteDocumentLoader: options.remoteDocumentLoader,
	}, nil
}

func save(store storage.Store, docs []ContextDocument) error {
	var ops []storage.Operation

	for _, doc := range docs {
		content, err := ld.DocumentFromReader(bytes.NewReader(doc.Content))
		if err != nil {
			return fmt.Errorf("document from reader: %w", err)
		}

		rd := ld.RemoteDocument{
			DocumentURL: doc.DocumentURL,
			Document:    content,
		}

		b, err := json.Marshal(rd)
		if err != nil {
			return fmt.Errorf("marshal remote document: %w", err)
		}

		ops = append(ops, storage.Operation{Key: doc.URL, Value: b})
	}

	// TODO: Support new/updated contexts on fresh storage and on the one with existing data (migrations).
	if err := store.Batch(ops); err != nil {
		return fmt.Errorf("store batch of contexts: %w", err)
	}

	return nil
}

// LoadDocument resolves JSON-LD context document by document URL (u) either from storage or from remote URL.
// If document is not found in the storage and remote DocumentLoader is not specified, ErrContextNotFound is returned.
func (l *DocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	b, err := l.store.Get(u)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get context from store: %w", err)
		}

		if l.remoteDocumentLoader == nil { // fetching from the remote URL is disabled
			return nil, ErrContextNotFound
		}

		return l.loadDocumentFromURL(u)
	}

	var rd ld.RemoteDocument

	if err := json.Unmarshal(b, &rd); err != nil {
		return nil, fmt.Errorf("unmarshal context document: %w", err)
	}

	return &rd, nil
}

func (l *DocumentLoader) loadDocumentFromURL(u string) (*ld.RemoteDocument, error) {
	rd, err := l.remoteDocumentLoader.LoadDocument(u)
	if err != nil {
		return nil, fmt.Errorf("load remote context document: %w", err)
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("marshal remote document: %w", err)
	}

	if err := l.store.Put(u, b); err != nil {
		return nil, fmt.Errorf("save remote document: %w", err)
	}

	return rd, nil
}

type documentLoaderOpts struct {
	remoteDocumentLoader ld.DocumentLoader
	extraContexts        []ContextDocument
}

// DocumentLoaderOpts configures DocumentLoader during creation.
type DocumentLoaderOpts func(opts *documentLoaderOpts)

// ContextDocument is a JSON-LD context document with associated metadata.
type ContextDocument struct {
	URL         string `json:"url"`                   // URL is a context URL that shows up in the documents.
	DocumentURL string `json:"documentURL,omitempty"` // The final URL of the loaded context document.
	Content     []byte `json:"content"`               // Content of the context document.
}

// WithExtraContexts sets the extra contexts (in addition to embedded) for preloading into the underlying storage.
func WithExtraContexts(contexts ...ContextDocument) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.extraContexts = contexts
	}
}

// WithRemoteDocumentLoader specifies loader for fetching JSON-LD context documents from remote URLs.
// Documents are fetched with this loader only if they are not found in the underlying storage.
func WithRemoteDocumentLoader(loader ld.DocumentLoader) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.remoteDocumentLoader = loader
	}
}
