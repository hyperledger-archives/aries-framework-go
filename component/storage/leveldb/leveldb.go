/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	pathPattern = "%s-%s"

	invalidTagName                  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue                 = `"%s" is an invalid tag value since it contains one or more ':' characters`
	tagMapKey                       = "TagMap"
	storeConfigKey                  = "StoreConfig"
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
	invalidQueryExpressionFormat    = `"%s" is not in a valid expression format. ` +
		"it must be in the following format: TagName:TagValue"
)

// Provider is a LevelDB implementation of the spi.Provider interface.
type Provider struct {
	dbPath string
	dbs    map[string]*store
	lock   sync.RWMutex
}

type closer func(storeName string)

type tagMapping map[string]map[string]struct{} // map[TagName](Set of database Keys)

type dbEntry struct {
	Value []byte        `json:"value,omitempty"`
	Tags  []storage.Tag `json:"tags,omitempty"`
}

// NewProvider instantiates Provider.
func NewProvider(dbPath string) *Provider {
	return &Provider{dbs: make(map[string]*store), dbPath: dbPath}
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, errors.New("store name cannot be blank")
	}

	name = strings.ToLower(name)

	store := p.getLeveldbStore(name)
	if store == nil {
		return p.newLeveldbStore(name)
	}

	return store, nil
}

// SetStoreConfig isn't needed for LevelDB. For consistency with other store implementations, it saves
// the store config for later retrieval.
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ToLower(name)

	openStore, ok := p.dbs[name]
	if !ok {
		return storage.ErrStoreNotFound
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal store configuration: %w", err)
	}

	err = openStore.Put(storeConfigKey, configBytes)
	if err != nil {
		return fmt.Errorf("failed to put store store configuration: %w", err)
	}

	return nil
}

// GetStoreConfig returns the current store configuration.
// TODO (#2948) When checking for the store, look for the underlying database instead of the stores open in memory
//              in order to comply with the interface docs.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	name = strings.ToLower(name)

	openStore, ok := p.dbs[name]
	if !ok {
		return storage.StoreConfiguration{}, storage.ErrStoreNotFound
	}

	storeConfigBytes, err := openStore.Get(storeConfigKey)
	if err != nil {
		return storage.StoreConfiguration{},
			fmt.Errorf(`failed to get store configuration for "%s": %w`, name, err)
	}

	var storeConfig storage.StoreConfiguration

	err = json.Unmarshal(storeConfigBytes, &storeConfig)
	if err != nil {
		return storage.StoreConfiguration{}, fmt.Errorf("failed to unmarshal store configuration: %w", err)
	}

	return storeConfig, nil
}

// GetOpenStores returns all Stores currently open in the Provider.
func (p *Provider) GetOpenStores() []storage.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]storage.Store, len(p.dbs))

	var counter int

	for _, db := range p.dbs {
		openStores[counter] = db
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	p.lock.RLock()

	openStoresSnapshot := make([]*store, len(p.dbs))

	var counter int

	for _, openStore := range p.dbs {
		openStoresSnapshot[counter] = openStore
		counter++
	}
	p.lock.RUnlock()

	for _, openStore := range openStoresSnapshot {
		err := openStore.Close()
		if err != nil {
			return fmt.Errorf(`failed to close open store with name "%s": %w`, openStore.name, err)
		}
	}

	return nil
}

// getLeveldbStore finds level db store with given name
// returns nil if not found.
func (p *Provider) getLeveldbStore(name string) *store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return p.dbs[name]
}

// newLeveldbStore creates level db store for given name space
// returns nil if not found.
func (p *Provider) newLeveldbStore(name string) (*store, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	db, err := leveldb.OpenFile(fmt.Sprintf(pathPattern, p.dbPath, name), nil)
	if err != nil {
		return nil, err
	}

	store := &store{db: db, name: name, close: p.removeStore}
	p.dbs[name] = store

	return store, nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.dbs[name]
	if ok {
		delete(p.dbs, name)
	}
}

type store struct {
	db    *leveldb.DB
	name  string
	close closer
	lock  sync.RWMutex
}

// Put stores the key and the record.
// WARNING: When storing tags, a race condition can occur if this is called from two different store objects
// that point to the same underlying database at the same time, causing the tag map to be incorrect. You will need
// to add locks.
// TODO (#2947) This current implementation doesn't update the tag map if tags is empty, but this isn't correct.
//              An empty tags slice should remove any stored tags for this key-value pair.
func (s *store) Put(key string, value []byte, tags ...storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be blank")
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

	var newDBEntry dbEntry
	newDBEntry.Value = value

	if len(tags) > 0 {
		newDBEntry.Tags = tags

		err := s.updateTagMap(key, tags)
		if err != nil {
			return fmt.Errorf("failed to update tag map: %w", err)
		}
	}

	entryBytes, err := json.Marshal(newDBEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal new DB entry: %w", err)
	}

	return s.db.Put([]byte(key), entryBytes, nil)
}

// Get fetches the record based on key.
func (s *store) Get(k string) ([]byte, error) {
	retrievedDBEntry, err := s.getDBEntry(k)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	return retrievedDBEntry.Value, nil
}

func (s *store) GetTags(key string) ([]storage.Tag, error) {
	retrievedDBEntry, err := s.getDBEntry(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	return retrievedDBEntry.Tags, nil
}

// TODO (#2605) proper bulk retrieval implementation. This is just a naive implementation that ensures this method
//  can at least return the expected results without failing. It doesn't take advantage of LevelDB features that may
//  allow for faster bulk retrieval.
func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	values := make([][]byte, len(keys))

	for i, key := range keys {
		var err error
		values[i], err = s.Get(key)

		if err != nil {
			if errors.Is(err, storage.ErrDataNotFound) {
				continue
			}

			return nil, fmt.Errorf("unexpected failure while retrieving the value stored under %s: %w", key, err)
		}
	}

	return values, nil
}

// This provider doesn't currently support any of the current query options.
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		return nil, err
	}

	if expression == "" {
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}

	expressionSplit := strings.Split(expression, ":")

	var expressionTagName string

	var expressionTagValue string

	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName = expressionSplit[0]
	case expressionTagNameAndValueLength:
		expressionTagName = expressionSplit[0]
		expressionTagValue = expressionSplit[1]
	default:
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}

	matchingDatabaseKeys, err := s.getDatabaseKeysMatchingQuery(expressionTagName, expressionTagValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get database keys matching query: %w", err)
	}

	return &iterator{keys: matchingDatabaseKeys, store: s}, nil
}

// Delete will delete record with k key.
// WARNING: If this store has any tags, a race condition can occur if this is called from two different store objects
// that point to the same underlying database at the same time, causing the tag map to be incorrect. You will need
// to add locks.
func (s *store) Delete(key string) error {
	if key == "" {
		return errors.New("key cannot be blank")
	}

	err := s.db.Delete([]byte(key), nil)
	if err != nil {
		return fmt.Errorf("failed to delete from underlying database")
	}

	err = s.removeFromTagMap(key)
	if err != nil {
		return fmt.Errorf("failed to remove key from tag map: %w", err)
	}

	return nil
}

// TODO (#2605) proper bulk retrieval implementation. This is just a naive implementation that ensures this method
//  can at least perform the operations as expected without failing. It doesn't take advantage of LevelDB features that
//  may allow for faster batch operations.
func (s *store) Batch(operations []storage.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	for _, operation := range operations {
		if operation.Value == nil {
			err := s.Delete(operation.Key)
			if err != nil {
				return fmt.Errorf("failed to delete value: %w", err)
			}
		} else {
			err := s.Put(operation.Key, operation.Value, operation.Tags...)
			if err != nil {
				return fmt.Errorf("failed to put value: %w", err)
			}
		}
	}

	return nil
}

// This store doesn't queue values, so there's never anything to flush.
func (s *store) Flush() error {
	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.db.Close()
	if err != nil {
		if err.Error() != "leveldb: closed" {
			return err
		}
	}

	return nil
}

func (s *store) updateTagMap(key string, tags []storage.Tag) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	tagMap, err := s.getTagMap(true)
	if err != nil {
		return fmt.Errorf("failed to get tag map: %w", err)
	}

	for _, tag := range tags {
		if tagMap[tag.Name] == nil {
			tagMap[tag.Name] = make(map[string]struct{})
		}

		tagMap[tag.Name][key] = struct{}{}
	}

	tagMapBytes, err := json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) getDBEntry(key string) (dbEntry, error) {
	if key == "" {
		return dbEntry{}, errors.New("key cannot be blank")
	}

	retrievedDBEntryBytes, err := s.db.Get([]byte(key), nil)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return dbEntry{}, storage.ErrDataNotFound
		}

		return dbEntry{}, err
	}

	var retrievedDBEntry dbEntry

	err = json.Unmarshal(retrievedDBEntryBytes, &retrievedDBEntry)
	if err != nil {
		return dbEntry{}, fmt.Errorf("failed to unmarshal retrieved DB entry: %w", err)
	}

	return retrievedDBEntry, nil
}

func (s *store) removeFromTagMap(keyToRemove string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	tagMap, err := s.getTagMap(false)
	if err != nil {
		// If there's no tag map, then this means that tags have never been used. This means that there's no tag map
		// to update. This isn't a problem.
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil
		}

		return fmt.Errorf("failed to get tag map: %w", err)
	}

	for _, tagNameToKeys := range tagMap {
		delete(tagNameToKeys, keyToRemove)
	}

	tagMapBytes, err := json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) getDatabaseKeysMatchingQuery(expressionTagName, expressionTagValue string) ([]string, error) {
	tagMap, err := s.getTagMap(false)
	if err != nil {
		// If there's no tag map, then this means that tags have never been used, and therefore no matching results.
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, nil
		}

		return nil, fmt.Errorf("failed to get tag map: %w", err)
	}

	if expressionTagValue == "" {
		return getDatabaseKeysMatchingTagName(tagMap, expressionTagName), nil
	}

	matchingDatabaseKeys, err := s.getDatabaseKeysMatchingTagNameAndValue(tagMap, expressionTagName, expressionTagValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get database keys matching tag name and value: %w", err)
	}

	return matchingDatabaseKeys, nil
}

func (s *store) getDatabaseKeysMatchingTagNameAndValue(tagMap tagMapping,
	expressionTagName, expressionTagValue string) ([]string, error) {
	var matchingDatabaseKeys []string

	for tagName, databaseKeysSet := range tagMap {
		if tagName == expressionTagName {
			for databaseKey := range databaseKeysSet {
				tags, err := s.GetTags(databaseKey)
				if err != nil {
					return nil, fmt.Errorf("failed to get tags: %w", err)
				}

				for _, tag := range tags {
					if tag.Name == expressionTagName && tag.Value == expressionTagValue {
						matchingDatabaseKeys = append(matchingDatabaseKeys, databaseKey)

						break
					}
				}
			}

			break
		}
	}

	return matchingDatabaseKeys, nil
}

func (s *store) getTagMap(createIfDoesNotExist bool) (tagMapping, error) {
	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		if createIfDoesNotExist && errors.Is(err, storage.ErrDataNotFound) {
			// Create the tag map if it has never been created before.
			err = s.Put(tagMapKey, []byte("{}"))
			if err != nil {
				return nil, fmt.Errorf(`failed to create tag map for "%s": %w`, s.name, err)
			}

			tagMapBytes = []byte("{}")
		} else {
			return nil, fmt.Errorf("failed to get tag map: %w", err)
		}
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	return tagMap, nil
}

type iterator struct {
	keys         []string
	currentIndex int
	currentKey   string
	store        *store
}

func (i *iterator) Next() (bool, error) {
	if len(i.keys) == i.currentIndex || len(i.keys) == 0 {
		if len(i.keys) == i.currentIndex || len(i.keys) == 0 {
			return false, nil
		}
	}

	i.currentKey = i.keys[i.currentIndex]

	i.currentIndex++

	return true, nil
}

func (i *iterator) Key() (string, error) {
	return i.currentKey, nil
}

func (i *iterator) Value() ([]byte, error) {
	value, err := i.store.Get(i.currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from store: %w", err)
	}

	return value, nil
}

func (i *iterator) Tags() ([]storage.Tag, error) {
	tags, err := i.store.GetTags(i.currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from store: %w", err)
	}

	return tags, nil
}

func (i *iterator) TotalItems() (int, error) {
	return len(i.keys), nil
}

func (i *iterator) Close() error {
	return nil
}

func getQueryOptions(options []storage.QueryOption) storage.QueryOptions {
	var queryOptions storage.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func checkForUnsupportedQueryOptions(options []storage.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("levelDB provider does not currently support " +
			"setting the initial page number of query results")
	}

	if querySettings.SortOptions != nil {
		return errors.New("levelDB provider does not currently support custom sort options for query results")
	}

	return nil
}

func getDatabaseKeysMatchingTagName(tagMap tagMapping, expressionTagName string) []string {
	var matchingDatabaseKeys []string

	for tagName, databaseKeysSet := range tagMap {
		if tagName == expressionTagName {
			for databaseKey := range databaseKeysSet {
				matchingDatabaseKeys = append(matchingDatabaseKeys, databaseKey)
			}

			break
		}
	}

	return matchingDatabaseKeys
}
