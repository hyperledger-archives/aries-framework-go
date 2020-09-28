/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"fmt"
)

const (
	failOpenUnderlyingStore      = "failed to open underlying store: %w"
	failCloseUnderlyingStore     = "failed to close underlying store: %w"
	failCloseAllUnderlyingStores = "failed to close all underlying stores: %w"

	failFormat                  = "failed to format value: %w"
	failPutInUnderlyingStore    = "failed to put encrypted document in underlying store: %w"
	failGetFromUnderlyingStore  = "failed to get formatted value from underlying store: %w"
	failParseFormattedValue     = "failed to parse formatted value: %w"
	failDeleteInUnderlyingStore = "failed to delete key-value pair in underlying store: %w"
)

// Formatter represents a type that can convert data between two formats.
type Formatter interface {
	Format([]byte) ([]byte, error)
	ParseValue([]byte) ([]byte, error)
}

// FormattedProvider is a storage provider that allows for data to be formatted in an underlying provider.
type FormattedProvider struct {
	provider  Provider
	formatter Formatter
}

// NewFormattedProvider instantiates a new FormattedProvider with the given Provider and Formatter.
// The Formatter is used to format data before being sent to the Provider for storage.
// The Formatter is also used to restore the original format of data being retrieved from Provider.
func NewFormattedProvider(provider Provider, formatter Formatter) *FormattedProvider {
	return &FormattedProvider{
		provider:  provider,
		formatter: formatter,
	}
}

// OpenStore opens a store in the underlying provider with the given name and returns a handle to it.
func (p *FormattedProvider) OpenStore(name string) (Store, error) {
	store, err := p.provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf(failOpenUnderlyingStore, err)
	}

	edvStore := formatStore{
		store:     store,
		formatter: p.formatter,
	}

	return &edvStore, nil
}

// CloseStore closes the store with the given name in the underlying provider.
func (p *FormattedProvider) CloseStore(name string) error {
	err := p.provider.CloseStore(name)
	if err != nil {
		return fmt.Errorf(failCloseUnderlyingStore, err)
	}

	return p.provider.CloseStore(name)
}

// Close closes all stores created in the underlying provider.
func (p *FormattedProvider) Close() error {
	err := p.provider.Close()
	if err != nil {
		return fmt.Errorf(failCloseAllUnderlyingStores, err)
	}

	return p.provider.Close()
}

type formatStore struct {
	store     Store
	formatter Formatter
}

func (s *formatStore) Put(k string, v []byte) error {
	formattedValue, err := s.formatter.Format(v)
	if err != nil {
		return fmt.Errorf(failFormat, err)
	}

	err = s.store.Put(k, formattedValue)
	if err != nil {
		return fmt.Errorf(failPutInUnderlyingStore, err)
	}

	return nil
}

func (s *formatStore) Get(k string) ([]byte, error) {
	formattedValue, err := s.store.Get(k)
	if err != nil {
		return nil, fmt.Errorf(failGetFromUnderlyingStore, err)
	}

	value, err := s.formatter.ParseValue(formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failParseFormattedValue, err)
	}

	return value, nil
}

func (s *formatStore) Iterator(startKey, endKey string) StoreIterator {
	return s.store.Iterator(startKey, endKey)
}

func (s *formatStore) Delete(k string) error {
	err := s.store.Delete(k)
	if err != nil {
		return fmt.Errorf(failDeleteInUnderlyingStore, err)
	}

	return nil
}
