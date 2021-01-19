/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

// Provider represents an in-memory implementation of the newstorage.Provider interface.
type Provider struct {
	dbs map[string]*memStore
	sync.RWMutex
}

type closer func(storeName string)

// NewProvider instantiates a new in-memory storage Provider.
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*memStore)}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (newstorage.Store, error) {
	storeName := strings.ToLower(name)

	p.Lock()
	defer p.Unlock()

	store := p.dbs[storeName]
	if store == nil {
		newStore := &memStore{name: storeName, db: make(map[string]dbEntry), close: p.removeStore}
		p.dbs[storeName] = newStore

		return newStore, nil
	}

	return store, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping newstorage.ErrStoreNotFound will be returned.
func (p *Provider) SetStoreConfig(name string, config newstorage.StoreConfiguration) error {
	storeName := strings.ToLower(name)

	p.Lock()
	defer p.Unlock()

	store := p.dbs[storeName]
	if store == nil {
		return newstorage.ErrStoreNotFound
	}

	store.config = config

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping newstorage.ErrStoreNotFound will be returned.
func (p *Provider) GetStoreConfig(name string) (newstorage.StoreConfiguration, error) {
	storeName := strings.ToLower(name)

	store := p.dbs[storeName]
	if store == nil {
		return newstorage.StoreConfiguration{}, newstorage.ErrStoreNotFound
	}

	return store.config, nil
}

// Close closes all stores created under this store provider. All data will be deleted.
func (p *Provider) Close() error {
	for _, memStore := range p.dbs {
		err := memStore.Close()
		if err != nil {
			return fmt.Errorf("failed to close a mem store: %w", err)
		}
	}

	p.dbs = make(map[string]*memStore)

	return nil
}

func (p *Provider) removeStore(name string) {
	p.Lock()
	defer p.Unlock()

	_, ok := p.dbs[name]
	if ok {
		delete(p.dbs, name)
	}
}

type dbEntry struct {
	value []byte
	tags  []newstorage.Tag
}

type memStore struct {
	name   string
	db     map[string]dbEntry
	config newstorage.StoreConfiguration
	close  closer
	sync.RWMutex
}

// Put stores the key + value pair along with the (optional) tags.
func (m *memStore) Put(key string, value []byte, tags ...newstorage.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	m.Lock()
	defer m.Unlock()
	m.db[key] = dbEntry{
		value: value,
		tags:  tags,
	}

	return nil
}

// Get fetches the value associated with the given key.
// If key cannot be found, then an error wrapping newstorage.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *memStore) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	m.RLock()
	defer m.RUnlock()
	entry, ok := m.db[key]

	if !ok {
		return nil, newstorage.ErrDataNotFound
	}

	return entry.value, nil
}

// Get fetches all tags associated with the given key.
// If key cannot be found, then an error wrapping newstorage.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *memStore) GetTags(key string) ([]newstorage.Tag, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	m.RLock()
	defer m.RUnlock()
	entry, ok := m.db[key]

	if !ok {
		return nil, newstorage.ErrDataNotFound
	}

	return entry.tags, nil
}

// GetBulk fetches the values associated with the given keys.
// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
// If any of the given keys are empty, then an error will be returned.
func (m *memStore) GetBulk(keys ...string) ([][]byte, error) {
	if keys == nil {
		return nil, errors.New("keys string slice cannot be nil")
	}

	for _, key := range keys {
		if key == "" {
			return nil, errEmptyKey
		}
	}

	values := make([][]byte, len(keys))

	m.RLock()
	defer m.RUnlock()

	for i, key := range keys {
		values[i] = m.db[key].value
	}

	return values, nil
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// memStore does not make use of newstorage.QueryOptions.
func (m *memStore) Query(expression string, _ ...newstorage.QueryOption) (newstorage.Iterator, error) {
	if expression == "" {
		return &memIterator{}, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		m.RLock()
		defer m.RUnlock()

		keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, "")

		return &memIterator{keys: keys, dbEntries: dbEntries}, nil
	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		m.RLock()
		defer m.RUnlock()

		keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, expressionTagValue)

		return &memIterator{keys: keys, dbEntries: dbEntries}, nil
	default:
		return &memIterator{}, errInvalidQueryExpressionFormat
	}
}

// Delete deletes the key + value pair (and all tags) associated with key.
// If key is empty, then an error will be returned.
func (m *memStore) Delete(k string) error {
	if k == "" {
		return errEmptyKey
	}

	m.Lock()
	defer m.Unlock()
	delete(m.db, k)

	return nil
}

// Batch performs multiple Put and/or Delete operations in order.
// If any of the given keys are empty, then an error will be returned.
func (m *memStore) Batch(operations []newstorage.Operation) error {
	m.Lock()
	defer m.Unlock()

	for _, operation := range operations {
		if operation.Key == "" {
			return errEmptyKey
		}
	}

	for _, operation := range operations {
		if operation.Value == nil {
			delete(m.db, operation.Key)
			continue
		}

		m.db[operation.Key] = dbEntry{
			value: operation.Value,
			tags:  operation.Tags,
		}
	}

	return nil
}

// Close closes this store object. All data within the store is deleted.
func (m *memStore) Close() error {
	m.Lock()
	defer m.Unlock()

	m.close(m.name)

	return nil
}

func (m *memStore) getMatchingKeysAndDBEntries(tagName, tagValue string) ([]string, []dbEntry) {
	var matchAnyValue bool
	if tagValue == "" {
		matchAnyValue = true
	}

	var keys []string

	var dbEntries []dbEntry

	for key, dbEntry := range m.db {
		for _, tag := range dbEntry.tags {
			if tag.Name == tagName && (matchAnyValue || tag.Value == tagValue) {
				keys = append(keys, key)
				dbEntries = append(dbEntries, dbEntry)

				break
			}
		}
	}

	return keys, dbEntries
}

// memIterator represents a snapshot of some set of entries in a memStore.
type memIterator struct {
	currentIndex   int
	currentKey     string
	currentDBEntry dbEntry
	keys           []string
	dbEntries      []dbEntry
}

// Next moves the pointer to the next entry in the iterator. It returns false if the iterator is exhausted.
func (m *memIterator) Next() (bool, error) {
	if len(m.dbEntries) == m.currentIndex || len(m.dbEntries) == 0 {
		return false, nil
	}

	m.currentKey = m.keys[m.currentIndex]
	m.currentDBEntry = m.dbEntries[m.currentIndex]
	m.currentIndex++

	return true, nil
}

// Key returns the key of the current entry.
func (m *memIterator) Key() (string, error) {
	if len(m.keys) == 0 {
		return "", errIteratorExhausted
	}

	return m.currentKey, nil
}

// Value returns the value of the current entry.
func (m *memIterator) Value() ([]byte, error) {
	if len(m.keys) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.value, nil
}

// Tags returns the tags associated with the key of the current entry.
func (m *memIterator) Tags() ([]newstorage.Tag, error) {
	if len(m.keys) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.tags, nil
}

// Close is a no-op, since there's nothing to close for a memIterator.
func (m *memIterator) Close() error {
	return nil
}
