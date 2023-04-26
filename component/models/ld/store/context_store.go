/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/log"
	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// ContextStoreName is a JSON-LD context store name.
	ContextStoreName = "ldcontexts"

	// ContextRecordTag is a tag associated with every record in the store.
	ContextRecordTag = "record"
)

var logger = log.New("aries-framework/store/ld")

// ContextStore represents a repository for JSON-LD context operations.
type ContextStore interface {
	Get(u string) (*jsonld.RemoteDocument, error)
	Put(u string, rd *jsonld.RemoteDocument) error
	Import(documents []ldcontext.Document) error
	Delete(documents []ldcontext.Document) error
}

// ContextStoreImpl is a default implementation of JSON-LD context repository.
type ContextStoreImpl struct {
	store storage.Store
}

// NewContextStore returns a new instance of ContextStoreImpl.
func NewContextStore(storageProvider storage.Provider) (*ContextStoreImpl, error) {
	store, err := storageProvider.OpenStore(ContextStoreName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	err = storageProvider.SetStoreConfig(ContextStoreName,
		storage.StoreConfiguration{TagNames: []string{ContextRecordTag}})
	if err != nil {
		return nil, fmt.Errorf("set store config: %w", err)
	}

	return &ContextStoreImpl{store: store}, nil
}

// Get returns JSON-LD remote document from the underlying storage by context url.
func (s *ContextStoreImpl) Get(u string) (*jsonld.RemoteDocument, error) {
	b, err := s.store.Get(u)
	if err != nil {
		return nil, fmt.Errorf("get context from store: %w", err)
	}

	var rd jsonld.RemoteDocument

	if err := json.Unmarshal(b, &rd); err != nil {
		return nil, fmt.Errorf("unmarshal context document: %w", err)
	}

	return &rd, nil
}

// Put saves JSON-LD remote document into the underlying storage under key u (context url).
func (s *ContextStoreImpl) Put(u string, rd *jsonld.RemoteDocument) error {
	b, err := json.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshal remote document: %w", err)
	}

	if err := s.store.Put(u, b); err != nil {
		return fmt.Errorf("put remote document: %w", err)
	}

	return nil
}

// Import imports JSON-LD contexts into the underlying storage.
func (s *ContextStoreImpl) Import(documents []ldcontext.Document) error {
	hashes, err := computeContextHashes(s.store)
	if err != nil {
		return fmt.Errorf("compute context hashes: %w", err)
	}

	var contexts []ldcontext.Document

	for _, c := range documents {
		b, er := getRemoteDocumentBytes(c)
		if er != nil {
			return fmt.Errorf("get remote document bytes: %w", er)
		}

		// filter out up-to-date contexts
		if computeHash(b) == hashes[c.URL] {
			continue
		}

		contexts = append(contexts, c)
	}

	// import context documents into the underlying storage
	if err = save(s.store, contexts); err != nil {
		return fmt.Errorf("save context documents: %w", err)
	}

	return nil
}

// Delete deletes matched context documents in the underlying storage.
// Documents are matched by context URL and ld.RemoteDocument content hash.
func (s *ContextStoreImpl) Delete(documents []ldcontext.Document) error {
	hashes, err := computeContextHashes(s.store)
	if err != nil {
		return fmt.Errorf("compute context hashes: %w", err)
	}

	for _, d := range documents {
		b, er := getRemoteDocumentBytes(d)
		if er != nil {
			return fmt.Errorf("get remote document bytes: %w", er)
		}

		// delete document only if content hashes match
		if computeHash(b) == hashes[d.URL] {
			if err := s.store.Delete(d.URL); err != nil {
				return fmt.Errorf("delete context document: %w", err)
			}
		}
	}

	return nil
}

func computeContextHashes(store storage.Store) (map[string]string, error) {
	iter, err := store.Query(ContextRecordTag)
	if err != nil {
		return nil, fmt.Errorf("query store: %w", err)
	}

	defer func() {
		er := iter.Close()
		if er != nil {
			logger.Errorf("Failed to close iterator: %s", er.Error())
		}
	}()

	contexts := make(map[string]string)

	for {
		if ok, err := iter.Next(); !ok || err != nil {
			if err != nil {
				return nil, fmt.Errorf("next entry: %w", err)
			}

			break
		}

		k, err := iter.Key()
		if err != nil {
			return nil, fmt.Errorf("get key: %w", err)
		}

		v, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("get value: %w", err)
		}

		contexts[k] = computeHash(v)
	}

	return contexts, nil
}

func computeHash(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func getRemoteDocumentBytes(d ldcontext.Document) ([]byte, error) {
	document, err := jsonld.DocumentFromReader(bytes.NewReader(d.Content))
	if err != nil {
		return nil, fmt.Errorf("document from reader: %w", err)
	}

	rd := jsonld.RemoteDocument{
		DocumentURL: d.DocumentURL,
		Document:    document,
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("marshal remote document: %w", err)
	}

	return b, nil
}

// save stores contexts into the underlying storage.
func save(store storage.Store, contexts []ldcontext.Document) error {
	for _, c := range contexts {
		b, err := getRemoteDocumentBytes(c)
		if err != nil {
			return fmt.Errorf("get remote document bytes: %w", err)
		}

		if err := store.Put(c.URL, b, storage.Tag{Name: ContextRecordTag}); err != nil {
			return fmt.Errorf("store context: %w", err)
		}
	}

	return nil
}
