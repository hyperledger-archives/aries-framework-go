/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package storage is not expected to be used by the mobile app.
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider represents a storage provider wrapper that allows for conversion between the
// spi/provider storage interfaces and the mobile-bindings-compatible interface in
// aries-framework-go/cmd/aries-agent-mobile/pkg/api/storage.go.
type Provider struct {
	mobileBindingProvider api.Provider
	openStores            map[string]*store
	lock                  sync.RWMutex
}

type closer func(name string)

// New returns a new storage provider wrapper.
func New(mobileBindingProvider api.Provider) *Provider {
	return &Provider{mobileBindingProvider: mobileBindingProvider, openStores: make(map[string]*store)}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
func (p *Provider) OpenStore(name string) (spi.Store, error) {
	name = strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	openStore := p.openStores[name]
	if openStore == nil {
		mobileBindingStore, err := p.mobileBindingProvider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open mobile binding store: %w", err)
		}

		storeWrapper := &store{mobileBindingStore: mobileBindingStore, name: name, close: p.removeStore}

		p.openStores[name] = storeWrapper

		return storeWrapper, nil
	}

	return openStore, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
// If name is blank, then an error will be returned.
func (p *Provider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	storeConfigBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal store config: %w", err)
	}

	err = p.mobileBindingProvider.SetStoreConfig(name, storeConfigBytes)
	if err != nil {
		// The errors returned from the mobile binding provider will just have the error text without any distinct
		// error types like the ones defined in aries-framework-go/spi/storage. In order to still allow for the use of
		// errors.Is(err, spi.ErrStoreNotFound) in higher level functions,
		// we need to wrap spi.ErrStoreNotFound back in if we detect it.
		if strings.Contains(err.Error(), spi.ErrStoreNotFound.Error()) {
			return fmt.Errorf("failed to set store config in mobile binding provider: %s: %w", err.Error(),
				spi.ErrStoreNotFound)
		}

		return fmt.Errorf("failed to set store config in mobile binding provider: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
// If name is blank, then an error will be returned.
func (p *Provider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	configBytes, err := p.mobileBindingProvider.GetStoreConfig(name)
	if err != nil {
		// The errors returned from the mobile binding provider will just have the error text without any distinct
		// error types like the ones defined in aries-framework-go/spi/storage. In order to still allow for the use of
		// errors.Is(err, spi.ErrStoreNotFound) in higher level functions,
		// we need to wrap spi.ErrStoreNotFound back in if we detect it.
		if strings.Contains(err.Error(), spi.ErrStoreNotFound.Error()) {
			return spi.StoreConfiguration{},
				fmt.Errorf("failed to get store config from mobile binding provider: %s: %w", err.Error(),
					spi.ErrStoreNotFound)
		}

		return spi.StoreConfiguration{},
			fmt.Errorf("failed to get store config from mobile binding provider: %w", err)
	}

	var storeConfig spi.StoreConfiguration

	err = json.Unmarshal(configBytes, &storeConfig)
	if err != nil {
		return spi.StoreConfiguration{}, fmt.Errorf("failed to unmarshal store configuration bytes: %w", err)
	}

	return storeConfig, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []spi.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openSPIStores := make([]spi.Store, len(p.openStores))

	var counter int

	for _, openStoreWrapper := range p.openStores {
		openSPIStores[counter] = openStoreWrapper
		counter++
	}

	return openSPIStores
}

// Close closes all stores created under this store provider.
// For persistent mobile binding store implementations, this does not delete any data in the underlying databases.
func (p *Provider) Close() error {
	p.lock.RLock()

	openStoresSnapshot := make([]*store, len(p.openStores))

	var counter int

	for _, openStore := range p.openStores {
		openStoresSnapshot[counter] = openStore
		counter++
	}
	p.lock.RUnlock()

	for _, openStore := range openStoresSnapshot {
		err := openStore.Close()
		if err != nil {
			return fmt.Errorf("failed to close store: %w", err)
		}
	}

	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.openStores, name)
}

type store struct {
	mobileBindingStore api.Store
	name               string
	close              closer
}

func (s *store) Put(key string, value []byte, tags ...spi.Tag) error {
	var tagsBytes []byte

	var err error

	if len(tags) > 0 {
		tagsBytes, err = json.Marshal(tags)
		if err != nil {
			return fmt.Errorf("failed to marshal tags: %w", err)
		}
	}

	err = s.mobileBindingStore.Put(key, value, tagsBytes)
	if err != nil {
		return fmt.Errorf("failed to put value in mobile binding store: %w", err)
	}

	return nil
}

// Get fetches the record based on key.
func (s *store) Get(k string) ([]byte, error) {
	res, err := s.mobileBindingStore.Get(k)
	if err != nil {
		// The errors returned from the mobile binding provider will just have the error text without any distinct
		// error types like the ones defined in aries-framework-go/spi/storage. In order to still allow for the use of
		// errors.Is(err, spi.ErrDataNotFound) in higher level functions,
		// we need to wrap spi.ErrDataNotFound back in if we detect it.
		if strings.Contains(err.Error(), spi.ErrDataNotFound.Error()) {
			return nil, fmt.Errorf("failed to get value from mobile binding store: %s: %w",
				err.Error(), spi.ErrDataNotFound)
		}

		return nil, fmt.Errorf("failed to get value from mobile binding store: %w", err)
	}

	return res, err
}

func (s *store) GetTags(k string) ([]spi.Tag, error) {
	tagsBytes, err := s.mobileBindingStore.GetTags(k)
	if err != nil {
		// The errors returned from the mobile binding provider will just have the error text without any distinct
		// error types like the ones defined in aries-framework-go/spi/storage. In order to still allow for the use of
		// errors.Is(err, spi.ErrDataNotFound) in higher level functions,
		// we need to wrap spi.ErrDataNotFound back in if we detect it.
		if strings.Contains(err.Error(), spi.ErrDataNotFound.Error()) {
			return nil, fmt.Errorf("failed to get tags from mobile binding store: %s: %w",
				err.Error(), spi.ErrDataNotFound)
		}

		return nil, fmt.Errorf("failed to get tags from mobile binding store: %w", err)
	}

	var tags []spi.Tag

	err = json.Unmarshal(tagsBytes, &tags)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	return tags, nil
}

func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	keysBytes, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keys: %w", err)
	}

	valuesBytes, err := s.mobileBindingStore.GetBulk(keysBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to get values from mobile binding store: %w", err)
	}

	var values [][]byte

	err = json.Unmarshal(valuesBytes, &values)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal values: %w", err)
	}

	return values, nil
}

func (s *store) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	var queryOptions spi.QueryOptions
	queryOptions.PageSize = 25

	for _, option := range options {
		option(&queryOptions)
	}

	mobileBindingIterator, err := s.mobileBindingStore.Query(expression, queryOptions.PageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to query mobile binding store: %w", err)
	}

	return &iterator{mobileBindingIterator: mobileBindingIterator}, nil
}

func (s *store) Delete(key string) error {
	err := s.mobileBindingStore.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete in mobile binding store: %w", err)
	}

	return nil
}

func (s *store) Batch(operations []spi.Operation) error {
	operationsBytes, err := json.Marshal(operations)
	if err != nil {
		return fmt.Errorf("failed to marshal operations: %w", err)
	}

	err = s.mobileBindingStore.Batch(operationsBytes)
	if err != nil {
		return fmt.Errorf("failed to execute batch operations in mobile binding store: %w", err)
	}

	return nil
}

func (s *store) Flush() error {
	err := s.mobileBindingStore.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush mobile binding store: %w", err)
	}

	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.mobileBindingStore.Close()
	if err != nil {
		return fmt.Errorf("failed to close mobile binding store: %w", err)
	}

	return nil
}

type iterator struct {
	mobileBindingIterator api.Iterator
}

func (i *iterator) Next() (bool, error) {
	next, err := i.mobileBindingIterator.Next()
	if err != nil {
		return false, fmt.Errorf("failed to move the entry pointer in the mobile binding iterator: %w", err)
	}

	return next, nil
}

func (i *iterator) Key() (string, error) {
	key, err := i.mobileBindingIterator.Key()
	if err != nil {
		return "", fmt.Errorf("failed to get key from mobile binding iterator: %w", err)
	}

	return key, nil
}

func (i *iterator) Value() ([]byte, error) {
	value, err := i.mobileBindingIterator.Value()
	if err != nil {
		return nil, fmt.Errorf("failed to get value from mobile binding iterator: %w", err)
	}

	return value, nil
}

func (i *iterator) Tags() ([]spi.Tag, error) {
	tagsBytes, err := i.mobileBindingIterator.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from mobile binding iterator: %w", err)
	}

	var tags []spi.Tag

	err = json.Unmarshal(tagsBytes, &tags)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	return tags, nil
}

func (i *iterator) TotalItems() (int, error) {
	return -1, errors.New("not implemented")
}

func (i *iterator) Close() error {
	err := i.mobileBindingIterator.Close()
	if err != nil {
		return fmt.Errorf("failed to close mobile binding iterator: %w", err)
	}

	return nil
}
