/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	didDoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockDidStore is mock did store
type MockDidStore struct {
	Store  map[string]*didDoc.Doc
	PutErr error
	GetErr error
}

// NewMockDidStore new didStore instance.
func NewMockDidStore() *MockDidStore {
	return &MockDidStore{Store: make(map[string]*didDoc.Doc)}
}

// Put stores the key and the record
func (m *MockDidStore) Put(doc *didDoc.Doc) error {
	k := doc.ID
	m.Store[k] = doc

	return m.PutErr
}

// Get fetches the record based on key
func (m *MockDidStore) Get(k string) (*didDoc.Doc, error) {
	val, ok := m.Store[k]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return val, m.GetErr
}
