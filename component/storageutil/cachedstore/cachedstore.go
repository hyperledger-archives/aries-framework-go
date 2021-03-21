/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cachedstore

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

type closer func(name string)

// CachedProvider is a spi.Provider that allows for automatic caching of data.
type CachedProvider struct {
	mainProvider  spi.Provider
	cacheProvider spi.Provider
	openStores    map[string]*store
	lock          sync.RWMutex
}

// NewProvider instantiates a new CachedProvider. It takes in two spi.Providers.
// mainProvider is the primary data source. It should be the slower storage provider.
// cacheProvider is the data source that will hold cached data. It should be the faster storage provider.
func NewProvider(mainProvider, cacheProvider spi.Provider) *CachedProvider {
	return &CachedProvider{
		mainProvider:  mainProvider,
		cacheProvider: cacheProvider,
		openStores:    make(map[string]*store),
	}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive.
func (c *CachedProvider) OpenStore(name string) (spi.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	name = strings.ToLower(name)

	c.lock.Lock()
	defer c.lock.Unlock()

	openStore, ok := c.openStores[name]
	if !ok {
		mainStore, err := c.mainProvider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open store in main provider: %w", err)
		}

		cacheStore, err := c.cacheProvider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open store in cache provider: %w", err)
		}

		newCachingStore := store{
			name:       name,
			mainStore:  mainStore,
			cacheStore: cacheStore,
			close:      c.removeStore,
		}

		c.openStores[name] = &newCachingStore

		return &newCachingStore, nil
	}

	return openStore, nil
}

// SetStoreConfig sets the configuration on a store.
func (c *CachedProvider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	err := c.mainProvider.SetStoreConfig(name, config)
	if err != nil {
		return fmt.Errorf("failed to set store configuration in main provider: %w", err)
	}

	err = c.cacheProvider.SetStoreConfig(name, config)
	if err != nil {
		return fmt.Errorf("failed to set store configuration in cache provider: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
func (c *CachedProvider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	config, err := c.mainProvider.GetStoreConfig(name)
	if err != nil {
		return spi.StoreConfiguration{},
			fmt.Errorf("failed to get store configuration from main provider: %w", err)
	}

	return config, nil
}

// GetOpenStores returns all currently open stores.
func (c *CachedProvider) GetOpenStores() []spi.Store {
	c.lock.RLock()
	defer c.lock.RUnlock()

	openStores := make([]spi.Store, len(c.openStores))

	var counter int

	for _, openStore := range c.openStores {
		openStores[counter] = openStore
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
// For persistent store implementations, this does not delete any data in the underlying databases.
func (c *CachedProvider) Close() error {
	err := c.mainProvider.Close()
	if err != nil {
		return fmt.Errorf("failed to close main provider: %w", err)
	}

	err = c.cacheProvider.Close()
	if err != nil {
		return fmt.Errorf("failed to close cache provider: %w", err)
	}

	return nil
}

func (c *CachedProvider) removeStore(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.openStores, name)
}

type store struct {
	name       string
	mainStore  spi.Store
	cacheStore spi.Store
	close      closer
}

func (s *store) Put(key string, value []byte, tags ...spi.Tag) error {
	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	err := s.mainStore.Put(key, value, tags...)
	if err != nil {
		return fmt.Errorf("failed to put key, values and tags in the main store: %w", err)
	}

	err = s.cacheStore.Put(key, value, tags...)
	if err != nil {
		return fmt.Errorf("failed to put key, values and tags in the cache store: %w", err)
	}

	return nil
}

func (s *store) Get(key string) ([]byte, error) {
	value, err := s.cacheStore.Get(key)
	if err == nil { // Cache hit.
		return value, nil
	} else if !errors.Is(err, spi.ErrDataNotFound) { // If err is spi.ErrDataNotFound, then it's a cache miss.
		return nil, fmt.Errorf("unexpected failure while getting data from cache store: %w", err)
	}

	value, err = s.mainStore.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from main store: %w", err)
	}

	err = s.cacheStore.Put(key, value)
	if err != nil {
		return nil,
			fmt.Errorf("failed to put the newly retrieved data into the cache store for future use: %w", err)
	}

	return value, nil
}

func (s *store) GetTags(key string) ([]spi.Tag, error) {
	tags, err := s.cacheStore.GetTags(key)
	if err == nil { // Cache hit.
		return tags, nil
	} else if !errors.Is(err, spi.ErrDataNotFound) {
		// If err is spi.ErrDataNotFound, then it's a cache miss. Anything else indicates some other problem.
		return nil, fmt.Errorf("unexpected failure while getting tags from the cache store: %w", err)
	}

	tags, err = s.mainStore.GetTags(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from the main store: %w", err)
	}

	return tags, nil
}

// TODO (#2476): Add caching support to this method by having it trying to fetch as many values as possible from
//  the cache provider, and only resort to the main provider for thos values that aren't found.
func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	values, err := s.mainStore.GetBulk(keys...)
	if err != nil {
		return nil, fmt.Errorf("failed to get values from the main store: %w", err)
	}

	return values, nil
}

// Can't use the cache store here since it might be missing data that's in the main store.
func (s *store) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	iterator, err := s.mainStore.Query(expression, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to query the main store: %w", err)
	}

	return iterator, err
}

func (s *store) Delete(key string) error {
	err := s.mainStore.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete data in the main store: %w", err)
	}

	err = s.cacheStore.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete data in the cache store: %w", err)
	}

	return nil
}

func (s *store) Batch(operations []spi.Operation) error {
	err := s.mainStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to perform operations in the main store: %w", err)
	}

	err = s.cacheStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to perform operations in the cache store: %w", err)
	}

	return nil
}

func (s *store) Flush() error {
	err := s.mainStore.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush the main store: %w", err)
	}

	err = s.cacheStore.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush the cache store: %w", err)
	}

	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.mainStore.Close()
	if err != nil {
		return fmt.Errorf("failed to close the main store: %w", err)
	}

	err = s.cacheStore.Close()
	if err != nil {
		return fmt.Errorf("failed to close the cache store: %w", err)
	}

	return nil
}
