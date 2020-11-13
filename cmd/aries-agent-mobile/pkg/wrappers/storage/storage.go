/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package storage is not expected to be used by the mobile app.
package storage

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider represents storage provider.
type Provider struct{ api.StorageProvider }

// New returns new storage provider.
func New(p api.StorageProvider) *Provider {
	return &Provider{StorageProvider: p}
}

// OpenStore overwrites original method to satisfy the interface.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	_store, err := p.StorageProvider.OpenStore(name)
	if err != nil {
		return nil, err
	}

	return &store{Store: _store}, nil
}

type store struct{ api.Store }

// Get fetches the record based on key.
func (s *store) Get(k string) ([]byte, error) {
	res, err := s.Store.Get(k)

	if err != nil && err.Error() == storage.ErrDataNotFound.Error() {
		return nil, storage.ErrDataNotFound
	}

	return res, err
}

// Iterator overwrites original method to satisfy the interface.
func (s *store) Iterator(startKey, endKey string) storage.StoreIterator {
	return &iterator{StoreIterator: s.Store.Iterator(startKey, endKey)}
}

type iterator struct{ api.StoreIterator }

// Release implements method to satisfy the interface.
func (s *iterator) Release() { s.StoreIterator.Free() }
