/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// TODO https://github.com/hyperledger/aries-framework-go/issues/750 - we will need to consider
//  automatic eviction based on TTL.

// Provider leveldb implementation of storage.Provider interface.
type Provider struct {
	dbs  map[string]*memStore
	lock sync.RWMutex
}

// NewProvider instantiates Provider.
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*memStore)}
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	store := p.getMemStore(name)
	if store == nil {
		return p.newMemStore(name), nil
	}

	return store, nil
}

// getMemStore finds mem store with given name
// returns nil if not found.
func (p *Provider) getMemStore(name string) *memStore {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.dbs[strings.ToLower(name)]
}

// newMemStore creates mem store for given name space
// returns nil if not found.
func (p *Provider) newMemStore(name string) *memStore {
	p.lock.Lock()
	defer p.lock.Unlock()

	store := &memStore{db: make(map[string][]byte)}
	p.dbs[strings.ToLower(name)] = store

	return store
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, memStore := range p.dbs {
		memStore.db = make(map[string][]byte)
	}

	p.dbs = make(map[string]*memStore)

	return nil
}

// CloseStore closes level db store of given name.
func (p *Provider) CloseStore(name string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	k := strings.ToLower(name)

	memStore, ok := p.dbs[k]
	if ok {
		delete(p.dbs, k)

		memStore.db = make(map[string][]byte)
	}

	return nil
}

type memStore struct {
	db map[string][]byte
	sync.RWMutex
}

// Put stores the key and the record.
func (s *memStore) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	s.Lock()
	s.db[k] = v
	s.Unlock()

	return nil
}

// Get fetches the record based on key.
func (s *memStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	s.RLock()
	data, ok := s.db[k]
	s.RUnlock()

	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return data, nil
}

// Iterator returns iterator for the latest snapshot of the underlying db.
func (s *memStore) Iterator(start, limit string) storage.StoreIterator {
	if limit == "" {
		return NewMemIterator(nil, nil)
	}

	s.RLock()
	data := s.db
	defer s.RUnlock()

	var batch [][]string

	var keys []string
	for k := range data {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	var (
		sIDx, eIDx = -1, len(keys)
		skip       bool
	)

	for i, k := range keys {
		if !skip && strings.HasPrefix(k, start) {
			sIDx = i
			skip = true
		}

		if strings.HasPrefix(k, strings.TrimSuffix(limit, storage.EndKeySuffix)) {
			eIDx = i

			if limit == k {
				break
			}

			eIDx++
		}
	}

	if sIDx == -1 {
		return NewMemIterator(nil, nil)
	}

	for _, k := range keys[sIDx:eIDx] {
		batch = append(batch, []string{k, string(data[k])})
	}

	return NewMemIterator(batch, nil)
}

// Delete will delete record with k key.
func (s *memStore) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	s.Lock()
	delete(s.db, k)
	s.Unlock()

	return nil
}

type memIterator struct {
	currentIndex int
	currentItem  []string
	items        [][]string
	err          error
}

// NewMemIterator returns new mem iterator for given batch.
func NewMemIterator(batch [][]string, errInitial error) storage.StoreIterator {
	if len(batch) == 0 {
		return &memIterator{err: errInitial}
	}

	return &memIterator{items: batch, err: errInitial}
}

func (s *memIterator) isExhausted() bool {
	return len(s.items) == 0 || len(s.items) == s.currentIndex
}

// Next moves pointer to next value of iterator.
// It returns false if the iterator is exhausted.
func (s *memIterator) Next() bool {
	if s.isExhausted() {
		return false
	}

	s.currentItem = s.items[s.currentIndex]
	s.currentIndex++

	return true
}

// Release releases associated resources.
func (s *memIterator) Release() {
	s.currentIndex = 0
	s.items = make([][]string, 0)
	s.currentItem = make([]string, 0)

	s.err = errors.New("iterator released")
}

// Error returns error in iterator.
func (s *memIterator) Error() error {
	return s.err
}

// Key returns the key of the current key/value pair.
func (s *memIterator) Key() []byte {
	if len(s.items) == 0 || len(s.currentItem) == 0 {
		return nil
	}

	return []byte(s.currentItem[0])
}

// Value returns the value of the current key/value pair.
func (s *memIterator) Value() []byte {
	if len(s.items) == 0 || len(s.currentItem) < 1 {
		return nil
	}

	return []byte(s.currentItem[1])
}
