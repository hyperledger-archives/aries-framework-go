/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package storage provides an alternative implementation of a mock Store, supporting most of a MemStore's behaviour
// with the added ability to override return values.
package storage

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
)

var (
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	Store              *MockStore
	Custom             storage.Store
	ErrOpenStoreHandle error
	ErrSetStoreConfig  error
	ErrClose           error
	ErrCloseStore      error
	FailNamespace      string
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{Store: &MockStore{
		Store: make(map[string]DBEntry),
	}}
}

// NewCustomMockStoreProvider new mock store provider instance
// from existing mock store.
func NewCustomMockStoreProvider(customStore storage.Store) *MockStoreProvider {
	return &MockStoreProvider{Custom: customStore}
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	if name == s.FailNamespace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
	}

	if s.Custom != nil {
		return s.Custom, s.ErrOpenStoreHandle
	}

	return s.Store, s.ErrOpenStoreHandle
}

// SetStoreConfig always return a nil error.
func (s *MockStoreProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return s.ErrSetStoreConfig
}

// GetStoreConfig is not implemented.
func (s *MockStoreProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

// GetOpenStores is not implemented.
func (s *MockStoreProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

// Close closes all stores created under this store provider.
func (s *MockStoreProvider) Close() error {
	return s.ErrClose
}

// CloseStore closes store for given name space.
func (s *MockStoreProvider) CloseStore(name string) error {
	return s.ErrCloseStore
}

// DBEntry is a value plus optional tags that are associated with some key.
type DBEntry struct {
	Value []byte
	Tags  []storage.Tag
}

// MockStore mock store.
type MockStore struct {
	Store     map[string]DBEntry
	lock      sync.RWMutex
	ErrPut    error
	ErrGet    error
	ErrDelete error
	ErrQuery  error
	ErrNext   error
	ErrValue  error
	ErrKey    error
	ErrBatch  error
	ErrClose  error
}

// Put stores the key and the record.
func (s *MockStore) Put(k string, v []byte, tags ...storage.Tag) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	if s.ErrPut != nil {
		return s.ErrPut
	}

	s.lock.Lock()
	s.Store[k] = DBEntry{
		Value: v,
		Tags:  tags,
	}
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the record based on key.
func (s *MockStore) Get(k string) ([]byte, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return entry.Value, s.ErrGet
}

// GetTags is not implemented.
func (s *MockStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

// GetBulk is not implemented.
func (s *MockStore) GetBulk(keys ...string) ([][]byte, error) {
	panic("implement me")
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
func (s *MockStore) Query(expression string, _ ...storage.QueryOption) (storage.Iterator, error) {
	if s.ErrQuery != nil {
		return nil, s.ErrQuery
	}

	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		s.lock.RLock()
		defer s.lock.RUnlock()

		keys, dbEntries := s.getMatchingKeysAndDBEntries(expressionTagName, "")

		return &iterator{keys: keys, dbEntries: dbEntries, errNext: s.ErrNext, errValue: s.ErrValue, errKey: s.ErrKey}, nil
	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		s.lock.RLock()
		defer s.lock.RUnlock()

		keys, dbEntries := s.getMatchingKeysAndDBEntries(expressionTagName, expressionTagValue)

		return &iterator{keys: keys, dbEntries: dbEntries, errNext: s.ErrNext, errValue: s.ErrValue, errKey: s.ErrKey}, nil
	default:
		return nil, errInvalidQueryExpressionFormat
	}
}

// Delete will delete record with k key.
func (s *MockStore) Delete(k string) error {
	s.lock.Lock()
	delete(s.Store, k)
	s.lock.Unlock()

	return s.ErrDelete
}

// Batch stores a batch of operations.
func (s *MockStore) Batch(operations []storage.Operation) error {
	if s.ErrBatch != nil {
		return s.ErrBatch
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	for _, op := range operations {
		s.Store[op.Key] = DBEntry{
			Value: op.Value,
			Tags:  op.Tags,
		}
	}

	return nil
}

// Flush is not implemented.
func (s *MockStore) Flush() error {
	panic("implement me")
}

// Close is not implemented.
func (s *MockStore) Close() error {
	return s.ErrClose
}

func (s *MockStore) getMatchingKeysAndDBEntries(tagName, tagValue string) ([]string, []DBEntry) {
	var matchAnyValue bool
	if tagValue == "" {
		matchAnyValue = true
	}

	var keys []string

	var dbEntries []DBEntry

	for key, dbEntry := range s.Store {
		for _, tag := range dbEntry.Tags {
			if tag.Name == tagName && (matchAnyValue || tag.Value == tagValue) {
				keys = append(keys, key)
				dbEntries = append(dbEntries, dbEntry)

				break
			}
		}
	}

	return keys, dbEntries
}

type iterator struct {
	currentIndex   int
	currentKey     string
	currentDBEntry DBEntry
	keys           []string
	dbEntries      []DBEntry
	errNext        error
	errValue       error
	errKey         error
}

func (m *iterator) Next() (bool, error) {
	if m.errNext != nil {
		return false, m.errNext
	}

	if len(m.dbEntries) == m.currentIndex || len(m.dbEntries) == 0 {
		m.dbEntries = nil
		return false, nil
	}

	m.currentKey = m.keys[m.currentIndex]
	m.currentDBEntry = m.dbEntries[m.currentIndex]
	m.currentIndex++

	return true, nil
}

func (m *iterator) Key() (string, error) {
	if m.errKey != nil {
		return "", m.errKey
	}

	if len(m.dbEntries) == 0 {
		return "", errIteratorExhausted
	}

	return m.currentKey, nil
}

func (m *iterator) Value() ([]byte, error) {
	if m.errValue != nil {
		return nil, m.errValue
	}

	if len(m.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.Value, nil
}

func (m *iterator) Tags() ([]storage.Tag, error) {
	if len(m.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}

	return m.currentDBEntry.Tags, nil
}

func (m *iterator) TotalItems() (int, error) {
	return -1, errors.New("not implemented")
}

func (m *iterator) Close() error {
	return nil
}
