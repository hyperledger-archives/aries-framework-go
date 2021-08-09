/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batchedstore

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
	failFlush       = "failure while flushing data: %w"
)

var errEmptyKey = errors.New("key cannot be empty")

// Provider is a spi.Provider that allows for data to be automatically batched.
// It acts as a wrapper around another storage provider (typically, one that would benefit from batching).
// TODO (#2484): Support batching across multiple stores for storage providers that inherently support this
//  (like the EDV REST provider, which uses a single underlying database (vault) for all of its stores).
type Provider struct {
	underlyingProvider spi.Provider
	openStores         map[string]*store
	batchSizeLimit     int
	lock               sync.RWMutex
}

type closer func(name string)

// NewProvider instantiates a new batched Provider.
func NewProvider(underlyingProvider spi.Provider, batchSizeLimit int) *Provider {
	return &Provider{
		underlyingProvider: underlyingProvider,
		openStores:         make(map[string]*store),
		batchSizeLimit:     batchSizeLimit,
	}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned by the underlying provider.
func (p *Provider) OpenStore(name string) (spi.Store, error) {
	name = strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	openStore, ok := p.openStores[name]
	if !ok {
		underlyingStore, err := p.underlyingProvider.OpenStore(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open store in underlying provider: %w", err)
		}

		newStore := store{
			name,
			underlyingStore,
			make([]spi.Operation, 0),
			p.batchSizeLimit,
			p.removeStore,
			&sync.RWMutex{},
		}
		p.openStores[name] = &newStore

		return &newStore, nil
	}

	return openStore, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned by the underlying provider.
// If name is blank, then an error will be returned by the underlying provider.
func (p *Provider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	err := p.underlyingProvider.SetStoreConfig(name, config)
	if err != nil {
		return fmt.Errorf("failed to set store config in underlying provider: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned by the underlying provider.
// If name is blank, then an error will be returned by the underlying provider.
func (p *Provider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	config, err := p.underlyingProvider.GetStoreConfig(name)
	if err != nil {
		return spi.StoreConfiguration{},
			fmt.Errorf("failed to get store config from underlying provider: %w", err)
	}

	return config, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []spi.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]spi.Store, len(p.openStores))

	var counter int

	for _, openStore := range p.openStores {
		openStores[counter] = openStore
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
// For persistent store implementations, this does not delete any data in the underlying databases.
func (p *Provider) Close() error {
	var openStoresSnapshot []*store

	p.lock.RLock()
	for _, openStore := range p.openStores {
		openStoresSnapshot = append(openStoresSnapshot, openStore)
	}
	p.lock.RUnlock()

	for _, openStore := range openStoresSnapshot {
		err := openStore.Close()
		if err != nil {
			return fmt.Errorf(`failed to close open store with name "%s": %w`, openStore.name, err)
		}
	}

	err := p.underlyingProvider.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying provider: %w", err)
	}

	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.openStores, name)
}

type store struct {
	name            string
	underlyingStore spi.Store
	currentBatch    []spi.Operation
	batchSizeLimit  int
	close           closer
	*sync.RWMutex
}

func (s *store) Put(key string, value []byte, tags ...spi.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	s.Lock()
	defer s.Unlock()

	s.currentBatch = append(s.currentBatch, spi.Operation{
		Key:   key,
		Value: value,
		Tags:  tags,
	})

	currentBatchLength := len(s.currentBatch)

	if currentBatchLength >= s.batchSizeLimit {
		err := s.flush()
		if err != nil {
			return fmt.Errorf(failFlush, err)
		}
	}

	return nil
}

// TODO (#2485): Check data in current batch before resorting to a flush.
func (s *store) Get(key string) ([]byte, error) {
	err := s.Flush()
	if err != nil {
		return nil, fmt.Errorf(failFlush, err)
	}

	value, err := s.underlyingStore.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from underlying store: %w", err)
	}

	return value, nil
}

func (s *store) GetTags(key string) ([]spi.Tag, error) {
	err := s.Flush()
	if err != nil {
		return nil, fmt.Errorf(failFlush, err)
	}

	tags, err := s.underlyingStore.GetTags(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from underlying store: %w", err)
	}

	return tags, nil
}

func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	err := s.Flush()
	if err != nil {
		return nil, fmt.Errorf(failFlush, err)
	}

	values, err := s.underlyingStore.GetBulk(keys...)
	if err != nil {
		return nil, fmt.Errorf("failed to get values from underlying store: %w", err)
	}

	return values, nil
}

func (s *store) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	err := s.Flush()
	if err != nil {
		return nil, fmt.Errorf(failFlush, err)
	}

	iterator, err := s.underlyingStore.Query(expression, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get values from underlying store: %w", err)
	}

	return iterator, nil
}

func (s *store) Delete(key string) error {
	if key == "" {
		return errEmptyKey
	}

	s.Lock()
	defer s.Unlock()

	s.currentBatch = append(s.currentBatch, spi.Operation{
		Key:   key,
		Value: nil,
	})

	currentBatchLength := len(s.currentBatch)

	if currentBatchLength >= s.batchSizeLimit {
		err := s.flush()
		if err != nil {
			return fmt.Errorf(failFlush, err)
		}
	}

	return nil
}

func (s *store) Batch(operations []spi.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	for _, operation := range operations {
		if operation.Key == "" {
			return errors.New("an operation's key was empty")
		}
	}

	for _, operation := range operations {
		s.Lock()

		s.currentBatch = append(s.currentBatch, operation)

		currentBatchLength := len(s.currentBatch)

		if currentBatchLength >= s.batchSizeLimit {
			err := s.flush()
			if err != nil {
				s.Unlock()
				return fmt.Errorf(failFlush, err)
			}
		}

		s.Unlock()
	}

	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.Flush()
	if err != nil {
		return fmt.Errorf(failFlush, err)
	}

	err = s.underlyingStore.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying store: %w", err)
	}

	return nil
}

// Grabs lock then flushes.
func (s *store) Flush() error {
	s.Lock()
	defer s.Unlock()

	return s.flush()
}

// Just flushes.
func (s *store) flush() error {
	if len(s.currentBatch) > 0 {
		err := s.underlyingStore.Batch(s.currentBatch)
		if err != nil {
			return fmt.Errorf("failure while executing batched operations: %w", err)
		}

		s.currentBatch = nil
	}

	return nil
}
