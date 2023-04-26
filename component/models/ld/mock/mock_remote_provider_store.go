/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// RemoteProviderStore is a mock remote JSON-LD context provider store.
type RemoteProviderStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrGetAll error
	ErrSave   error
	ErrDelete error
}

// NewMockRemoteProviderStore returns a new instance of RemoteProviderStore.
func NewMockRemoteProviderStore() *RemoteProviderStore {
	return &RemoteProviderStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}

// Get returns a remote provider record from the underlying storage.
func (s *RemoteProviderStore) Get(id string) (*store.RemoteProviderRecord, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	b, err := s.Store.Get(id)
	if err != nil {
		return nil, err
	}

	return &store.RemoteProviderRecord{
		ID:       id,
		Endpoint: string(b),
	}, nil
}

// GetAll returns all remote provider records from the underlying storage.
func (s *RemoteProviderStore) GetAll() ([]store.RemoteProviderRecord, error) {
	if s.ErrGetAll != nil {
		return nil, s.ErrGetAll
	}

	var records []store.RemoteProviderRecord

	for k, v := range s.Store.Store {
		records = append(records, store.RemoteProviderRecord{
			ID:       k,
			Endpoint: string(v.Value),
		})
	}

	return records, nil
}

// Save creates a new remote provider record and saves it to the underlying storage.
// If the record with specified endpoint already exists it is returned to the caller.
func (s *RemoteProviderStore) Save(endpoint string) (*store.RemoteProviderRecord, error) {
	if s.ErrSave != nil {
		return nil, s.ErrSave
	}

	for k, v := range s.Store.Store {
		if string(v.Value) == endpoint {
			return &store.RemoteProviderRecord{
				ID:       k,
				Endpoint: string(v.Value),
			}, nil
		}
	}

	id := uuid.New().String()

	if err := s.Store.Put(id, []byte(endpoint), storage.Tag{Name: store.RemoteProviderRecordTag}); err != nil {
		return nil, err
	}

	return &store.RemoteProviderRecord{
		ID:       id,
		Endpoint: endpoint,
	}, nil
}

// Delete deletes a remote provider record in the underlying storage.
func (s *RemoteProviderStore) Delete(id string) error {
	if s.ErrDelete != nil {
		return s.ErrDelete
	}

	return s.Store.Delete(id)
}
