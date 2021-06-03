/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider is a mocked implementation of spi.Provider.
type Provider struct {
	OpenStoreReturn spi.Store
	ErrOpenStore    error

	ErrSetStoreConfig error

	GetStoreConfigReturn spi.StoreConfiguration
	ErrGetStoreConfig    error

	GetOpenStoresReturn []spi.Store

	ErrClose error
}

// OpenStore returns mocked results.
func (p *Provider) OpenStore(string) (spi.Store, error) {
	return p.OpenStoreReturn, p.ErrOpenStore
}

// SetStoreConfig returns mocked results.
func (p *Provider) SetStoreConfig(string, spi.StoreConfiguration) error {
	return p.ErrSetStoreConfig
}

// GetStoreConfig returns mocked results.
func (p *Provider) GetStoreConfig(string) (spi.StoreConfiguration, error) {
	return p.GetStoreConfigReturn, p.ErrGetStoreConfig
}

// GetOpenStores returns mocked results.
func (p *Provider) GetOpenStores() []spi.Store {
	return p.GetOpenStoresReturn
}

// Close returns mocked results.
func (p *Provider) Close() error {
	return p.ErrClose
}

// Store is a mocked implementation of spi.Store.
type Store struct {
	ErrPut error

	GetReturn []byte
	ErrGet    error

	GetTagsReturn []spi.Tag
	ErrGetTags    error

	GetBulkReturn [][]byte
	ErrGetBulk    error

	QueryReturn spi.Iterator
	ErrQuery    error

	ErrDelete error

	ErrBatch error

	ErrFlush error

	ErrClose error
}

// Put returns mocked results.
func (s *Store) Put(string, []byte, ...spi.Tag) error {
	return s.ErrPut
}

// Get returns mocked results.
func (s *Store) Get(string) ([]byte, error) {
	return s.GetReturn, s.ErrGet
}

// GetTags returns mocked results.
func (s *Store) GetTags(string) ([]spi.Tag, error) {
	return s.GetTagsReturn, s.ErrGetTags
}

// GetBulk returns mocked results.
func (s *Store) GetBulk(...string) ([][]byte, error) {
	return s.GetBulkReturn, s.ErrGetBulk
}

// Query returns mocked results.
func (s *Store) Query(string, ...spi.QueryOption) (spi.Iterator, error) {
	return s.QueryReturn, s.ErrQuery
}

// Delete returns mocked results.
func (s *Store) Delete(string) error {
	return s.ErrDelete
}

// Batch returns mocked results.
func (s *Store) Batch([]spi.Operation) error {
	return s.ErrBatch
}

// Flush returns mocked results.
func (s *Store) Flush() error {
	return s.ErrFlush
}

// Close returns mocked results.
func (s *Store) Close() error {
	return s.ErrClose
}

// Iterator is a mocked implementation of spi.Iterator.
type Iterator struct {
	NextReturn bool
	ErrNext    error

	KeyReturn string
	ErrKey    error

	ValueReturn []byte
	ErrValue    error

	TagsReturn []spi.Tag
	ErrTags    error

	TotalItemsReturn int
	ErrTotalItems    error

	ErrClose error
}

// Next returns mocked results.
func (i *Iterator) Next() (bool, error) {
	return i.NextReturn, i.ErrNext
}

// Key returns mocked results.
func (i *Iterator) Key() (string, error) {
	return i.KeyReturn, i.ErrKey
}

// Value returns mocked results.
func (i *Iterator) Value() ([]byte, error) {
	return i.ValueReturn, i.ErrValue
}

// Tags returns mocked results.
func (i *Iterator) Tags() ([]spi.Tag, error) {
	return i.TagsReturn, i.ErrTags
}

// TotalItems returns mocked results.
func (i *Iterator) TotalItems() (int, error) {
	return i.TotalItemsReturn, i.ErrTotalItems
}

// Close returns mocked results.
func (i *Iterator) Close() error {
	return i.ErrClose
}
