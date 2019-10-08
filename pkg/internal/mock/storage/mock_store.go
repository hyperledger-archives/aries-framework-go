/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"errors"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	Custom             storage.Store
	Store              *MockStore
	ErrOpenStoreHandle error
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{Store: &MockStore{
		Store: make(map[string][]byte),
	}}
}

// NewMockCustomStoreProvider new customized store provider instance.
func NewMockCustomStoreProvider(custom storage.Store) *MockStoreProvider {
	return &MockStoreProvider{Custom: custom}
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	if s.Custom != nil {
		return s.Custom, s.ErrOpenStoreHandle
	}
	return s.Store, s.ErrOpenStoreHandle
}

// Close closes all stores created under this store provider
func (s *MockStoreProvider) Close() error {
	return nil
}

// CloseStore closes store for given name space
func (s *MockStoreProvider) CloseStore(name string) error {
	return nil
}

// MockStore mock store.
type MockStore struct {
	Store  map[string][]byte
	lock   sync.RWMutex
	ErrPut error
	ErrGet error
}

// Put stores the key and the record
func (s *MockStore) Put(k string, v []byte) error {
	if k == "" {
		return errors.New("key is mandatory")
	}
	s.lock.Lock()
	s.Store[k] = v
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the record based on key
func (s *MockStore) Get(k string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return val, s.ErrGet
}
