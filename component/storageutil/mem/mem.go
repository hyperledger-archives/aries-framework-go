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

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

// Provider represents an in-memory implementation of the spi.Provider interface.
type Provider struct {
	dbs  map[string]*memStore
	lock sync.RWMutex
}

type closer func(storeName string)

// NewProvider instantiates a new in-memory storage Provider.
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*memStore)}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (spi.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	storeName := strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

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
// If the store cannot be found, then an error wrapping spi.ErrStoreNotFound will be returned.
func (p *Provider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	storeName := strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	store := p.dbs[storeName]
	if store == nil {
		return spi.ErrStoreNotFound
	}

	store.config = config

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping spi.ErrStoreNotFound will be returned.
func (p *Provider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	storeName := strings.ToLower(name)

	store := p.dbs[storeName]
	if store == nil {
		return spi.StoreConfiguration{}, spi.ErrStoreNotFound
	}

	return store.config, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []spi.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]spi.Store, len(p.dbs))

	var counter int

	for _, db := range p.dbs {
		openStores[counter] = db
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.dbs = make(map[string]*memStore)

	return nil
}

// Ping always returns nil. It's here just to allow it to implement a "Pinger" sort of interface which may be defined
// somewhere and implemented by other storage implementations that use a remote database.
func (p *Provider) Ping() error {
	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.dbs[name]
	if ok {
		delete(p.dbs, name)
	}
}

type dbEntry struct {
	value []byte
	tags  []spi.Tag
}

type memStore struct {
	name   string
	db     map[string]dbEntry
	config spi.StoreConfiguration
	close  closer
	sync.RWMutex
}

// Put stores the key + value pair along with the (optional) tags.
func (m *memStore) Put(key string, value []byte, tags ...spi.Tag) error {
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

	m.Lock()
	defer m.Unlock()
	m.db[key] = dbEntry{
		value: value,
		tags:  tags,
	}

	return nil
}

// Get fetches the value associated with the given key.
// If key cannot be found, then an error wrapping spi.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *memStore) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	m.RLock()
	defer m.RUnlock()
	entry, ok := m.db[key]

	if !ok {
		return nil, spi.ErrDataNotFound
	}

	return entry.value, nil
}

// Get fetches all tags associated with the given key.
// If key cannot be found, then an error wrapping spi.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *memStore) GetTags(key string) ([]spi.Tag, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	m.RLock()
	defer m.RUnlock()
	entry, ok := m.db[key]

	if !ok {
		return nil, spi.ErrDataNotFound
	}

	return entry.tags, nil
}

// GetBulk fetches the values associated with the given keys.
// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
// If any of the given keys are empty, then an error will be returned.
func (m *memStore) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
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

type queryResult struct {
	keys      []string
	dbEntries []dbEntry
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// None of the current query options are supported
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
func (m *memStore) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		return nil, err
	}

	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	queryResults := make(map[string]*queryResult)

	for _, exp := range strings.Split(expression, "&&") {
		expressionSplit := strings.Split(exp, ":")
		switch len(expressionSplit) {
		case expressionTagNameOnlyLength:
			expressionTagName := expressionSplit[0]

			keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, "")

			queryResults[expressionTagName] = &queryResult{keys: keys, dbEntries: dbEntries}
		case expressionTagNameAndValueLength:
			expressionTagName := expressionSplit[0]
			expressionTagValue := expressionSplit[1]

			keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, expressionTagValue)

			queryResults[expressionTagName] = &queryResult{keys: keys, dbEntries: dbEntries}
		default:
			return nil, errInvalidQueryExpressionFormat
		}
	}

	keys, dbEntries := commonDBEntries(queryResults)

	return &memIterator{keys: keys, dbEntries: dbEntries}, nil
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
func (m *memStore) Batch(operations []spi.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

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
	m.close(m.name)

	return nil
}

// memStore doesn't queue values, so there's never anything to flush.
func (m *memStore) Flush() error {
	return nil
}

func (m *memStore) getMatchingKeysAndDBEntries(tagName, tagValue string) ([]string, []dbEntry) {
	var matchAnyValue bool
	if tagValue == "" {
		matchAnyValue = true
	}

	var keys []string

	var dbEntries []dbEntry

	m.RLock()
	defer m.RUnlock()

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
		m.dbEntries = nil
		return false, nil
	}

	m.currentKey = m.keys[m.currentIndex]
	m.currentDBEntry = m.dbEntries[m.currentIndex]
	m.currentIndex++

	return true, nil
}

// Key returns the key of the current entry.
func (m *memIterator) Key() (string, error) {
	if len(m.dbEntries) == 0 {
		return "", errIteratorExhausted
	}

	return m.currentKey, nil
}

// Value returns the value of the current entry.
func (m *memIterator) Value() ([]byte, error) {
	if len(m.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.value, nil
}

// Tags returns the tags associated with the key of the current entry.
func (m *memIterator) Tags() ([]spi.Tag, error) {
	if len(m.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.tags, nil
}

func (m *memIterator) TotalItems() (int, error) {
	return len(m.keys), nil
}

// Close is a no-op, since there's nothing to close for a memIterator.
func (m *memIterator) Close() error {
	return nil
}

func getQueryOptions(options []spi.QueryOption) spi.QueryOptions {
	var queryOptions spi.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func checkForUnsupportedQueryOptions(options []spi.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("in-memory provider does not currently support " +
			"setting the initial page number of query results")
	}

	if querySettings.SortOptions != nil {
		return errors.New("in-memory provider does not currently support custom sort options for query results")
	}

	return nil
}

// commonDBEntries returns the DB entries that appear in all the query results.
func commonDBEntries(results map[string]*queryResult) ([]string, []dbEntry) {
	numTags := len(results)
	keyMap := make(map[string]int)
	valueMap := make(map[string]dbEntry)

	for _, result := range results {
		for i, k := range result.keys {
			keyMap[k]++

			valueMap[k] = result.dbEntries[i]
		}
	}

	var keys []string

	var values []dbEntry

	for k, n := range keyMap {
		if n == numTags {
			keys = append(keys, k)

			values = append(values, valueMap[k])
		}
	}

	return keys, values
}
