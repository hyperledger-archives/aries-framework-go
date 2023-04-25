/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/google/uuid"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MockRemoteProviderStore is a mock remote JSON-LD context provider store.
type MockRemoteProviderStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrGetAll error
	ErrSave   error
	ErrDelete error
}

// NewMockRemoteProviderStore returns a new instance of MockRemoteProviderStore.
func NewMockRemoteProviderStore() *MockRemoteProviderStore {
	return &MockRemoteProviderStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}

// Get returns a remote provider record from the underlying storage.
func (m *MockRemoteProviderStore) Get(id string) (*ld.RemoteProviderRecord, error) {
	if m.ErrGet != nil {
		return nil, m.ErrGet
	}

	b, err := m.Store.Get(id)
	if err != nil {
		return nil, err
	}

	return &ld.RemoteProviderRecord{
		ID:       id,
		Endpoint: string(b),
	}, nil
}

// GetAll returns all remote provider records from the underlying storage.
func (m *MockRemoteProviderStore) GetAll() ([]ld.RemoteProviderRecord, error) {
	if m.ErrGetAll != nil {
		return nil, m.ErrGetAll
	}

	var records []ld.RemoteProviderRecord

	for k, v := range m.Store.Store {
		records = append(records, ld.RemoteProviderRecord{
			ID:       k,
			Endpoint: string(v.Value),
		})
	}

	return records, nil
}

// Save creates a new remote provider record and saves it to the underlying storage.
// If the record with specified endpoint already exists it is returned to the caller.
func (m *MockRemoteProviderStore) Save(endpoint string) (*ld.RemoteProviderRecord, error) {
	if m.ErrSave != nil {
		return nil, m.ErrSave
	}

	for k, v := range m.Store.Store {
		if string(v.Value) == endpoint {
			return &ld.RemoteProviderRecord{
				ID:       k,
				Endpoint: string(v.Value),
			}, nil
		}
	}

	id := uuid.New().String()

	if err := m.Store.Put(id, []byte(endpoint), storage.Tag{Name: ld.RemoteProviderRecordTag}); err != nil {
		return nil, err
	}

	return &ld.RemoteProviderRecord{
		ID:       id,
		Endpoint: endpoint,
	}, nil
}

// Delete deletes a remote provider record in the underlying storage.
func (m *MockRemoteProviderStore) Delete(id string) error {
	if m.ErrDelete != nil {
		return m.ErrDelete
	}

	return m.Store.Delete(id)
}
