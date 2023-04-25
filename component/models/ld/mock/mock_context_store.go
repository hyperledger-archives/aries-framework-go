/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"bytes"
	"encoding/json"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// ContextStore is a mock JSON-LD context store.
type ContextStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrPut    error
	ErrImport error
	ErrDelete error
}

// NewMockContextStore returns a new instance of ContextStore.
func NewMockContextStore() *ContextStore {
	return &ContextStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}

// Get returns JSON-LD remote document from the underlying storage by context url.
func (s *ContextStore) Get(u string) (*jsonld.RemoteDocument, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	b, err := s.Store.Get(u)
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
func (s *ContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	if s.ErrPut != nil {
		return s.ErrPut
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshal remote document: %w", err)
	}

	if err := s.Store.Put(u, b); err != nil {
		return fmt.Errorf("put remote document: %w", err)
	}

	return nil
}

// Import imports contexts into the underlying storage.
func (s *ContextStore) Import(documents []context.Document) error {
	if s.ErrImport != nil {
		return s.ErrImport
	}

	for _, d := range documents {
		document, err := jsonld.DocumentFromReader(bytes.NewReader(d.Content))
		if err != nil {
			return fmt.Errorf("document from reader: %w", err)
		}

		rd := jsonld.RemoteDocument{
			DocumentURL: d.DocumentURL,
			Document:    document,
		}

		b, err := json.Marshal(rd)
		if err != nil {
			return fmt.Errorf("marshal remote document: %w", err)
		}

		if err = s.Store.Put(d.URL, b, storage.Tag{Name: store.ContextRecordTag}); err != nil {
			return fmt.Errorf("put context document: %w", err)
		}
	}

	return nil
}

// Delete deletes context documents in the underlying storage.
func (s *ContextStore) Delete(documents []context.Document) error {
	if s.ErrDelete != nil {
		return s.ErrDelete
	}

	for _, d := range documents {
		if err := s.Store.Delete(d.URL); err != nil {
			return fmt.Errorf("delete context document: %w", err)
		}
	}

	return nil
}
