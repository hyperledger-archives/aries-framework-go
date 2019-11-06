/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem

import (
	"errors"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider leveldb implementation of storage.Provider interface
type Provider struct {
	dbs  map[string]*memStore
	lock sync.RWMutex
}

// NewProvider instantiates Provider
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
// returns nil if not found
func (p *Provider) getMemStore(name string) *memStore {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.dbs[strings.ToLower(name)]
}

// newMemStore creates mem store for given name space
// returns nil if not found
func (p *Provider) newMemStore(name string) *memStore {
	p.lock.Lock()
	defer p.lock.Unlock()

	store := &memStore{db: make(map[string][]byte)}
	p.dbs[strings.ToLower(name)] = store

	return store
}

// Close closes all stores created under this store provider
func (p *Provider) Close() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	for _, memStore := range p.dbs {
		memStore.db = make(map[string][]byte)
	}

	p.dbs = make(map[string]*memStore)

	return nil
}

// CloseStore closes level db store of given name
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

// Put stores the key and the record
// TODO - we will need to consider automatic eviction based on TTL.
func (s *memStore) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	s.Lock()
	s.db[k] = v
	s.Unlock()

	return nil
}

// Get fetches the record based on key
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
	panic("iterator not supported in mem store")
}
