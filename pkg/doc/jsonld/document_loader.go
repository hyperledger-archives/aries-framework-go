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
	"io"
	"io/fs"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// DefaultContextDBName is a default namespace in DB for storing JSON-LD contexts.
const DefaultContextDBName = "jsonldContexts"

var logger = log.New("aries-framework/jsonld")

// ErrContextNotFound is returned when JSON-LD context document is not found in the underlying storage.
var ErrContextNotFound = errors.New("context document not found")

// DocumentLoader is an implementation of ld.DocumentLoader interface from "json-gold" library backed by storage.
type DocumentLoader struct {
	store                storage.Store
	remoteDocumentLoader ld.DocumentLoader
}

// NewDocumentLoader returns a new DocumentLoader instance.
func NewDocumentLoader(storageProvider storage.Provider, opts ...DocumentLoaderOpts) (*DocumentLoader, error) {
	options := &documentLoaderOpts{
		contextDBName: DefaultContextDBName,
		contextFS:     EmbedFS,
		documents:     EmbedContexts,
	}

	for i := range opts {
		opts[i](options)
	}

	store, err := storageProvider.OpenStore(options.contextDBName)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	if len(options.documents) > 0 { // preload documents into the underlying storage
		if e := save(store, options.documents, options.contextFS); e != nil {
			return nil, fmt.Errorf("save context documents: %w", e)
		}
	}

	return &DocumentLoader{
		store:                store,
		remoteDocumentLoader: options.remoteDocumentLoader,
	}, nil
}

func save(store storage.Store, docs []ContextDocument, sys fs.FS) error {
	var ops []storage.Operation

	for _, doc := range docs {
		rd := ld.RemoteDocument{
			DocumentURL: doc.DocumentURL,
		}

		content := doc.Content

		if content == nil {
			c, err := loadFromFS(doc.Path, sys)
			if err != nil {
				return fmt.Errorf("load from FS: %w", err)
			}

			content = c
		}

		d, err := ld.DocumentFromReader(bytes.NewReader(content))
		if err != nil {
			return fmt.Errorf("document from reader: %w", err)
		}

		rd.Document = d

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

func loadFromFS(path string, sys fs.FS) ([]byte, error) {
	f, err := sys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() {
		if e := f.Close(); e != nil {
			logger.Errorf("close file: %w", e)
		}
	}()

	return io.ReadAll(f)
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

		return l.loadFromURL(u)
	}

	var rd ld.RemoteDocument

	if err := json.Unmarshal(b, &rd); err != nil {
		return nil, fmt.Errorf("unmarshal context document: %w", err)
	}

	return &rd, nil
}

func (l *DocumentLoader) loadFromURL(u string) (*ld.RemoteDocument, error) {
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
	contextDBName        string
	contextFS            fs.FS
	documents            []ContextDocument
}

// DocumentLoaderOpts configures DocumentLoader during creation.
type DocumentLoaderOpts func(opts *documentLoaderOpts)

// WithRemoteDocumentLoader specifies loader for fetching JSON-LD context documents from remote URLs.
// Documents are fetched with this loader only if they are not found in the underlying storage.
func WithRemoteDocumentLoader(loader ld.DocumentLoader) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.remoteDocumentLoader = loader
	}
}

// WithContextDBName specifies a name of DB where context documents are stored. If not set DefaultContextDBName is used.
func WithContextDBName(name string) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.contextDBName = name
	}
}

// WithContextFS specifies a file system with JSON-LD context documents for preloading.
func WithContextFS(sys fs.FS) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.contextFS = sys
	}
}

// ContextDocument is a JSON-LD context document with associated metadata.
// Content of the document can be set as a byte array via Content property or loaded from the file under Path.
type ContextDocument struct {
	// URL is a context URL that shows up in the documents.
	URL string
	// The final URL of the loaded context document.
	// Check https://www.w3.org/TR/json-ld11-api/#remotedocument for details.
	DocumentURL string
	// Content of the context document. If not set content is loaded from the file under Path.
	Content []byte
	// Path to the file with content of the context document.
	Path string
}

// WithContexts sets context documents for preloading into the underlying storage.
func WithContexts(docs ...ContextDocument) DocumentLoaderOpts {
	return func(opts *documentLoaderOpts) {
		opts.documents = docs
	}
}
