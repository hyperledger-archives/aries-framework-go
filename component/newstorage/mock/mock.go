/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/newstorage"
)

// Provider is a mocked implementation of newstorage.Provider.
type Provider struct {
	OpenStoreReturn      newstorage.Store
	ErrOpenStore         error
	ErrSetStoreConfig    error
	GetStoreConfigReturn newstorage.StoreConfiguration
	ErrGetStoreConfig    error
}

// OpenStore returns mocked results.
func (p *Provider) OpenStore(string) (newstorage.Store, error) {
	return p.OpenStoreReturn, p.ErrOpenStore
}

// SetStoreConfig returns mocked results.
func (p *Provider) SetStoreConfig(string, newstorage.StoreConfiguration) error {
	return p.ErrSetStoreConfig
}

// GetStoreConfig returns mocked results.
func (p *Provider) GetStoreConfig(string) (newstorage.StoreConfiguration, error) {
	return p.GetStoreConfigReturn, p.ErrGetStoreConfig
}

// GetOpenStores returns mocked results.
func (p *Provider) GetOpenStores() []newstorage.Store {
	return nil
}

// Close returns mocked results.
func (p *Provider) Close() error {
	return errors.New("close failure")
}

// Store is a mocked implementation of newstorage.Store.
type Store struct {
	ErrPut    error
	GetReturn []byte
	ErrGet    error
	ErrQuery  error
}

// Put returns mocked results.
func (s *Store) Put(string, []byte, ...newstorage.Tag) error {
	return s.ErrPut
}

// Get returns mocked results.
func (s *Store) Get(string) ([]byte, error) {
	return s.GetReturn, s.ErrGet
}

// GetTags returns mocked results.
func (s *Store) GetTags(string) ([]newstorage.Tag, error) {
	return nil, nil
}

// GetBulk returns mocked results.
func (s *Store) GetBulk(...string) ([][]byte, error) {
	panic("implement me")
}

// Query returns mocked results.
func (s *Store) Query(string, ...newstorage.QueryOption) (newstorage.Iterator, error) {
	return &Iterator{}, s.ErrQuery
}

// Delete returns mocked results.
func (s *Store) Delete(string) error {
	panic("implement me")
}

// Batch returns mocked results.
func (s *Store) Batch([]newstorage.Operation) error {
	return errors.New("batch failure")
}

// Flush returns mocked results.
func (s *Store) Flush() error {
	return errors.New("flush failure")
}

// Close returns mocked results.
func (s *Store) Close() error {
	return errors.New("close failure")
}

// Iterator is a mocked implementation of newstorage.Iterator.
type Iterator struct {
}

// Next returns mocked results.
func (i *Iterator) Next() (bool, error) {
	return false, errors.New("next failure")
}

// Key returns mocked results.
func (i *Iterator) Key() (string, error) {
	return "", errors.New("key failure")
}

// Value returns mocked results.
func (i *Iterator) Value() ([]byte, error) {
	return nil, errors.New("value failure")
}

// Tags returns mocked results.
func (i *Iterator) Tags() ([]newstorage.Tag, error) {
	return nil, errors.New("tags failure")
}

// Close returns mocked results.
func (i *Iterator) Close() error {
	return errors.New("close failure")
}
