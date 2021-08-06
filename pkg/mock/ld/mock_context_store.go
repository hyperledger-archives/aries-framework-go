/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"bytes"
	"encoding/json"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MockContextStore is a mock JSON-LD context store.
type MockContextStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrPut    error
	ErrImport error
	ErrDelete error
}

// NewMockContextStore returns a new instance of MockContextStore.
func NewMockContextStore() *MockContextStore {
	return &MockContextStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}

// Get returns JSON-LD remote document from the underlying storage by context url.
func (m *MockContextStore) Get(u string) (*jsonld.RemoteDocument, error) {
	if m.ErrGet != nil {
		return nil, m.ErrGet
	}

	b, err := m.Store.Get(u)
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
func (m *MockContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	if m.ErrPut != nil {
		return m.ErrPut
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshal remote document: %w", err)
	}

	if err := m.Store.Put(u, b); err != nil {
		return fmt.Errorf("put remote document: %w", err)
	}

	return nil
}

// Import imports contexts into the underlying storage.
func (m *MockContextStore) Import(documents []ldcontext.Document) error {
	if m.ErrImport != nil {
		return m.ErrImport
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

		if err = m.Store.Put(d.URL, b, storage.Tag{Name: ld.ContextRecordTag}); err != nil {
			return fmt.Errorf("put context document: %w", err)
		}
	}

	return nil
}

// Delete deletes context documents in the underlying storage.
func (m *MockContextStore) Delete(documents []ldcontext.Document) error {
	if m.ErrDelete != nil {
		return m.ErrDelete
	}

	for _, d := range documents {
		if err := m.Store.Delete(d.URL); err != nil {
			return fmt.Errorf("delete context document: %w", err)
		}
	}

	return nil
}
