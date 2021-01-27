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
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
)

const failFlush = "failure while flushing data: %w"

var (
	logger      = log.New("batchedstore")
	errEmptyKey = errors.New("key cannot be empty")
)

// Provider is a newstorage.Provider that allows for data to be automatically batched.
// It acts as a wrapper around another storage provider (typically, one that would benefit from batching).
// TODO (#2484): Support batching across multiple stores for storage providers that inherently support this
//  (like the EDV REST provider, which uses a single underlying database (vault) for all of its stores).
type Provider struct {
	underlyingProvider newstorage.Provider
	openStores         map[string]*store
	batchSizeLimit     int
	lock               sync.RWMutex
}

type closer func(name string)

// NewProvider instantiates a new batched Provider.
func NewProvider(underlyingProvider newstorage.Provider, batchSizeLimit int) *Provider {
	return &Provider{
		underlyingProvider: underlyingProvider,
		openStores:         make(map[string]*store),
		batchSizeLimit:     batchSizeLimit,
	}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned by the underlying provider.
func (p *Provider) OpenStore(name string) (newstorage.Store, error) {
	storeName := strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	openStore, ok := p.openStores[storeName]
	if !ok {
		underlyingStore, err := p.underlyingProvider.OpenStore(storeName)
		if err != nil {
			return nil, fmt.Errorf("failed to open store in underlying provider: %w", err)
		}

		newStore := store{
			storeName,
			underlyingStore,
			make([]newstorage.Operation, 0),
			p.batchSizeLimit,
			p.removeStore,
			&sync.RWMutex{},
		}
		p.openStores[storeName] = &newStore

		return &newStore, nil
	}

	return openStore, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned by the underlying provider.
// If name is blank, then an error will be returned by the underlying provider.
func (p *Provider) SetStoreConfig(name string, config newstorage.StoreConfiguration) error {
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
func (p *Provider) GetStoreConfig(name string) (newstorage.StoreConfiguration, error) {
	config, err := p.underlyingProvider.GetStoreConfig(name)
	if err != nil {
		return newstorage.StoreConfiguration{},
			fmt.Errorf("failed to get store config from underlying provider: %w", err)
	}

	return config, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []newstorage.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]newstorage.Store, len(p.openStores))

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
	underlyingStore newstorage.Store
	currentBatch    []newstorage.Operation
	batchSizeLimit  int
	close           closer
	*sync.RWMutex
}

func (s *store) Put(key string, value []byte, tags ...newstorage.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	s.Lock()
	defer s.Unlock()

	s.currentBatch = append(s.currentBatch, newstorage.Operation{
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

func (s *store) GetTags(key string) ([]newstorage.Tag, error) {
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

func (s *store) Query(expression string, options ...newstorage.QueryOption) (newstorage.Iterator, error) {
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

	s.currentBatch = append(s.currentBatch, newstorage.Operation{
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

func (s *store) Batch(operations []newstorage.Operation) error {
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
		startFlushTime := time.Now()

		err := s.underlyingStore.Batch(s.currentBatch)
		if err != nil {
			return fmt.Errorf("failure while executing batched operations: %w", err)
		}

		s.currentBatch = nil

		logger.Debugf(`store with name "%s" finished flushing data. Time taken: %s`, s.name, time.Since(startFlushTime))
	}

	return nil
}
