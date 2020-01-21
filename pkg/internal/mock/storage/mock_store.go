/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	Store              *MockStore
	StoreWithDelete    *MockStoreWithDelete
	Custom             storage.Store
	ErrOpenStoreHandle error
	FailNamespace      string
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{Store: &MockStore{
		Store: make(map[string][]byte),
	}}
}

// NewCustomMockStoreProvider new mock store provider instance
// from existing mock store
func NewCustomMockStoreProvider(customStore storage.Store) *MockStoreProvider {
	return &MockStoreProvider{Custom: customStore}
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	if name == s.FailNamespace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
	}

	if s.Custom != nil {
		return s.Custom, s.ErrOpenStoreHandle
	}

	return s.Store, s.ErrOpenStoreHandle
}

// OpenStoreWithDelete opens and returns a store with Delete capability for given name space.
func (s *MockStoreProvider) OpenStoreWithDelete(name string) (storage.StoreWithDelete, error) {
	if name == s.FailNamespace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
	}

	return s.StoreWithDelete, s.ErrOpenStoreHandle
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
	ErrItr error
}

// MockStoreWithDelete mock store with delete capability
type MockStoreWithDelete struct {
	MockStore
}

// Put stores the key and the record
func (s *MockStore) Put(k string, v []byte) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	if s.ErrPut != nil {
		return s.ErrPut
	}

	s.lock.Lock()
	s.Store[k] = v
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the record based on key
func (s *MockStore) Get(k string) ([]byte, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return val, s.ErrGet
}

// Iterator returns an iterator for the underlying mockstore
func (s *MockStore) Iterator(start, limit string) storage.StoreIterator {
	if s.ErrItr != nil {
		return NewMockIteratorWithError(s.ErrItr)
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	var batch [][]string

	for k, v := range s.Store {
		if strings.HasPrefix(k, start) {
			batch = append(batch, []string{k, string(v)})
		}
	}

	return NewMockIterator(batch)
}

// Delete will delete record with k key
func (s *MockStoreWithDelete) Delete(k string) error {
	s.lock.Lock()
	delete(s.Store, k)
	s.lock.Unlock()

	return nil
}

// NewMockIterator returns new mock iterator for given batch
func NewMockIterator(batch [][]string) *MockIterator {
	if len(batch) == 0 {
		return &MockIterator{}
	}

	return &MockIterator{items: batch}
}

// NewMockIteratorWithError returns new mock iterator with error
func NewMockIteratorWithError(err error) *MockIterator {
	return &MockIterator{err: err}
}

// MockIterator is the mock implementation of storage iterator
type MockIterator struct {
	currentIndex int
	currentItem  []string
	items        [][]string
	err          error
}

func (s *MockIterator) isExhausted() bool {
	return len(s.items) == 0 || len(s.items) == s.currentIndex
}

// Next moves pointer to next value of iterator.
// It returns false if the iterator is exhausted.
func (s *MockIterator) Next() bool {
	if s.isExhausted() {
		return false
	}

	s.currentItem = s.items[s.currentIndex]
	s.currentIndex++

	return true
}

// Release releases associated resources.
func (s *MockIterator) Release() {
	s.currentIndex = 0
	s.items = make([][]string, 0)
	s.currentItem = make([]string, 0)
}

// Error returns error in iterator.
func (s *MockIterator) Error() error {
	return s.err
}

// Key returns the key of the current key/value pair.
func (s *MockIterator) Key() []byte {
	if len(s.items) == 0 || len(s.currentItem) == 0 {
		return nil
	}

	return []byte(s.currentItem[0])
}

// Value returns the value of the current key/value pair.
func (s *MockIterator) Value() []byte {
	if len(s.items) == 0 || len(s.currentItem) < 1 {
		return nil
	}

	return []byte(s.currentItem[1])
}
