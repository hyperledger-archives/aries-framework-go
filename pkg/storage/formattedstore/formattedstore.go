/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	failOpenUnderlyingStore      = "failed to open underlying store: %w"
	failCloseUnderlyingStore     = "failed to close underlying store: %w"
	failCloseAllUnderlyingStores = "failed to close all underlying stores: %w"

	failFormat                         = "failed to format value: %w"
	failPutInUnderlyingStore           = "failed to put encrypted document in underlying store: %w"
	failGetFromUnderlyingStore         = "failed to get formatted value from underlying store: %w"
	failParseFormattedValue            = "failed to parse formatted value: %w"
	failDeleteInUnderlyingStore        = "failed to delete key-value pair in underlying store: %w"
	failGetIteratorFromUnderlyingStore = "failed to get iterator from underlying store: %w"
)

// Formatter represents a type that can convert data between two formats.
type Formatter interface {
	FormatPair(k string, v []byte) ([]byte, error)
	ParsePair([]byte) (k string, v []byte, err error)
}

// FormattedProvider is a storage provider that allows for data to be formatted in an underlying provider.
type FormattedProvider struct {
	provider              storage.Provider
	formatter             Formatter
	skipIteratorFiltering bool
}

// NewFormattedProvider instantiates a new FormattedProvider with the given Provider and Formatter.
// The Formatter is used to format data before being sent to the Provider for storage.
// The Formatter is also used to restore the original format of data being retrieved from Provider.
// If the underlying provider already does filtering using the startKey and endKey parameters in its
// Iterator(startKey, endKey string) method, then set skipIteratorFiltering to true to avoid redundant
// filtering in FormattedProvider.
func NewFormattedProvider(provider storage.Provider, formatter Formatter,
	skipIteratorFiltering bool) *FormattedProvider {
	return &FormattedProvider{
		provider:              provider,
		formatter:             formatter,
		skipIteratorFiltering: skipIteratorFiltering,
	}
}

// OpenStore opens a store in the underlying provider with the given name and returns a handle to it.
func (p *FormattedProvider) OpenStore(name string) (storage.Store, error) {
	store, err := p.provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf(failOpenUnderlyingStore, err)
	}

	formatStore := formatStore{
		store:                 store,
		formatter:             p.formatter,
		skipIteratorFiltering: p.skipIteratorFiltering,
	}

	return &formatStore, nil
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
	store                 storage.Store
	formatter             Formatter
	skipIteratorFiltering bool
}

func (s *formatStore) Put(k string, v []byte) error {
	formattedValue, err := s.formatter.FormatPair(k, v)
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

	_, value, err := s.formatter.ParsePair(formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failParseFormattedValue, err)
	}

	return value, nil
}

// The "don't filter" switch is here since it's possible for the underlying storage to have already done
// the filtering, in which case it would be redundant to do it here too.
// TODO (#2315) While doing the storage interface rework, see if the skipIteratorFiltering switch is still
//  needed.
func (s *formatStore) Iterator(startKey, endKey string) storage.StoreIterator {
	formattedIterator := s.store.Iterator(startKey, endKey)

	err := formattedIterator.Error()
	if err != nil {
		return mem.NewMemIterator(nil, fmt.Errorf(failGetIteratorFromUnderlyingStore, err))
	}

	var batch [][]string

	for formattedIterator.Next() {
		key, value, err := s.formatter.ParsePair(formattedIterator.Value())
		if err != nil {
			return mem.NewMemIterator(nil, fmt.Errorf(failParseFormattedValue, err))
		}

		if s.skipIteratorFiltering {
			batch = append(batch, []string{key, string(value)})
		} else {
			if endKey == "" {
				return mem.NewMemIterator(nil, nil)
			}

			if strings.HasPrefix(key, strings.TrimSuffix(endKey, storage.EndKeySuffix)) && key != endKey {
				batch = append(batch, []string{key, string(value)})
				continue
			}

			if key >= startKey && key < endKey {
				batch = append(batch, []string{key, string(value)})
			}
		}
	}

	formattedIterator.Release()

	return mem.NewMemIterator(batch, nil)
}

func (s *formatStore) Delete(k string) error {
	err := s.store.Delete(k)
	if err != nil {
		return fmt.Errorf(failDeleteInUnderlyingStore, err)
	}

	return nil
}
