/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"fmt"
	"sync"
)

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	store MockStore
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{store: MockStore{
		store: make(map[string][]byte),
	}}
}

// GetStoreHandle returns a store.
func (s *MockStoreProvider) GetStoreHandle() (*MockStore, error) {
	return &s.store, nil
}

// Close closes the store provider.
func (s *MockStoreProvider) Close() error {
	return nil
}

// MockStore mock store.
type MockStore struct {
	store map[string][]byte
	lock  sync.RWMutex
}

// Put stores the key and the record
func (s *MockStore) Put(k string, v []byte) error {
	s.lock.Lock()
	s.store[k] = v
	s.lock.Unlock()

	return nil
}

// Get fetches the record based on key
func (s *MockStore) Get(k string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.store[k]
	if !ok {
		return nil, fmt.Errorf("no value found for the key %s", k)
	}

	return val, nil
}
