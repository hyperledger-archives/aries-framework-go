/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	Store              *MockStore
	ErrOpenStoreHandle error
	FailNameSpace      string
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{Store: &MockStore{
		Store: make(map[string][]byte),
	}}
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	if name == s.FailNameSpace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
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
