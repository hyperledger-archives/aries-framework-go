/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb

import (
	"errors"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider leveldb implementation of storage.Provider interface
type Provider struct {
	db *leveldb.DB
}

// NewProvider instantiates Provider
func NewProvider(dbPath string) (*Provider, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &Provider{db}, nil
}

// GetStoreHandle returns a handle to the store
func (provider *Provider) GetStoreHandle() (storage.Store, error) {
	return newLeveldbStore(provider.db), nil
}

// Close closes the underlying provider
func (provider *Provider) Close() error {
	return provider.db.Close()
}

type leveldbStore struct {
	db *leveldb.DB
}

func newLeveldbStore(db *leveldb.DB) *leveldbStore {
	return &leveldbStore{db}
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
		return nil, err
	}
	return data, nil
}
