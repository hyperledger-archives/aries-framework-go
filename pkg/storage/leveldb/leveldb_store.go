// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const pathPattern = "%s-%s"

// Provider leveldb implementation of storage.Provider interface
type Provider struct {
	dbPath string
	dbs    map[string]*leveldbStore
	lock   sync.RWMutex
}

// NewProvider instantiates Provider
func NewProvider(dbPath string) *Provider {
	return &Provider{dbs: make(map[string]*leveldbStore), dbPath: dbPath}
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	store := p.getLeveldbStore(name)
	if store == nil {
		return p.newLeveldbStore(name)
	}

	return store, nil
}

// getLeveldbStore finds level db store with given name
// returns nil if not found
func (p *Provider) getLeveldbStore(name string) *leveldbStore {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.dbs[strings.ToLower(name)]
}

// newLeveldbStore creates level db store for given name space
// returns nil if not found
func (p *Provider) newLeveldbStore(name string) (*leveldbStore, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	db, err := leveldb.OpenFile(fmt.Sprintf(pathPattern, p.dbPath, name), nil)
	if err != nil {
		return nil, err
	}

	store := &leveldbStore{db}
	p.dbs[strings.ToLower(name)] = store

	return store, nil
}

// Close closes all stores created under this store provider
func (p *Provider) Close() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	var errs []error

	for _, v := range p.dbs {
		e := v.db.Close()
		if e != nil && e != leveldb.ErrClosed {
			errs = append(errs, e)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to close stores, %v", errs)
	}

	p.dbs = make(map[string]*leveldbStore)

	return nil
}

// CloseStore closes level db store of given name
func (p *Provider) CloseStore(name string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	k := strings.ToLower(name)

	store, ok := p.dbs[k]
	if ok {
		delete(p.dbs, k)
		return store.db.Close()
	}

	return nil
}

type leveldbStore struct {
	db *leveldb.DB
}

// Put stores the key and the record
func (s *leveldbStore) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	return s.db.Put([]byte(k), v, nil)
}

// Get fetches the record based on key
func (s *leveldbStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	data, err := s.db.Get([]byte(k), nil)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, storage.ErrDataNotFound
		}

		return nil, err
	}

	return data, nil
}

// Iterator returns iterator for the latest snapshot of the underlying db.
func (s *leveldbStore) Iterator(start, limit string) storage.StoreIterator {
	if start == "" || limit == "" {
		iterator.NewEmptyIterator(errors.New("start or limit key is mandatory"))
	}

	return s.db.NewIterator(&util.Range{Start: []byte(start),
		Limit: []byte(strings.ReplaceAll(limit, storage.EndKeySuffix, "~"))}, nil)
}

// Delete will delete record with k key
func (s *leveldbStore) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	return s.db.Delete([]byte(k), nil)
}
