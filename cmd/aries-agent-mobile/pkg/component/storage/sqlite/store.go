/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Created using https://github.com/hyperledger/aries-framework-go-ext/tree/main/component/storage/mysql as reference.

package sqlite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3" //nolint:gci // required for SQLite

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	tagMapKey      = "TagMap"
	storeConfigKey = "StoreConfig"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
)

const (
	invalidQueryExpressionFormat = `"%s" is not in a valid expression format. ` +
		"it must be in the following format: TagName:TagValue"
	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

// TODO: Fully implement all methods.

// ErrKeyRequired is returned when key is mandatory.
var ErrKeyRequired = errors.New("key is mandatory")

type closer func(storeName string)

type tagMapping map[string]map[string]struct{} // map[TagName](Set of database Keys)

type dbEntry struct {
	Value []byte        `json:"value,omitempty"`
	Tags  []storage.Tag `json:"tags,omitempty"`
}

// Provider represents a SQLite DB implementation of the storage.Provider interface.
type Provider struct {
	dbPath   string
	db       *sql.DB
	dbs      map[string]*store
	dbPrefix string
	lock     sync.RWMutex
}

// Option configures the SQLite provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// GetProvider is used to be able to get the SQLite provider and expose it in Android.
func GetProvider(dbPath string) api.Provider {
	provider, err := NewProvider(dbPath)
	if err != nil {
		panic(fmt.Errorf(failureWhileOpeningSQLiteConnectionErrMsg, dbPath, err))
	}

	return provider
}

// NewProvider instantiates Provider.
// Example DB Path ./test.db
// This provider's CreateStore(name) implementation creates stores that are backed by a table without a schema.
// The fully qualified name of the table is thus `name`.
// Use of `Batch()` has additional considerations - please read the docs for Batch() accordingly.
func NewProvider(dbPath string, opts ...Option) (*Provider, error) {
	if dbPath == "" {
		return nil, errBlankDBPath
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningSQLiteConnectionErrMsg, dbPath, err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf(failureWhilePingingSQLiteErrMsg, dbPath, err)
	}

	p := &Provider{
		dbPath: dbPath,
		db:     db,
		dbs:    map[string]*store{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
// SQLite doesn't support the "-" character in the table names so they are replaced with "_"
// WARNING: This method will create a database and table based on the given name. Those database calls may be
// vulnerable to an SQL injection attack. Be very careful if you use a user-provided string in the store name!
func (p *Provider) OpenStore(name string) (api.Store, error) {
	if name == "" {
		return nil, errBlankStoreName
	}

	name = strings.ReplaceAll(strings.ToLower(name), "-", "_")

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	createTableStmt := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s "+
		"('key' VARCHAR(255) NOT NULL PRIMARY KEY, 'value' MEDIUMBLOB)", name)

	// creating key-value table inside the database
	_, err := p.db.Exec(createTableStmt)
	if err != nil {
		return nil, fmt.Errorf(failureWhileCreatingTableErrMsg, name, err)
	}

	// Opening new DB connection
	storeDB, err := sql.Open("sqlite3", p.dbPath)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningSQLiteConnectionErrMsg, p.dbPath, err)
	}

	store := &store{
		db:        storeDB,
		name:      name,
		tableName: name,
		close:     p.removeStore,
	}

	p.dbs[name] = store

	return store, nil
}

// SetStoreConfig sets the configuration on a store. This must be done before storing any data in order to make use
// of the Query method.
// TODO: Use proper SQlite indexing instead of the "Tag Map".
func (p *Provider) SetStoreConfig(name string, storeConfigBytes []byte) error {
	config := storage.StoreConfiguration{}

	err := json.Unmarshal(storeConfigBytes, &config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal store configuration: %w", err)
	}

	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ReplaceAll(strings.ToLower(name), "-", "_")

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	openStore, ok := p.dbs[name]
	if !ok {
		return storage.ErrStoreNotFound
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal store configuration: %w", err)
	}

	err = openStore.Put(storeConfigKey, configBytes, []byte{})
	if err != nil {
		return fmt.Errorf("failed to put store store configuration: %w", err)
	}

	return nil
}

// GetStoreConfig returns the store's configuration.
// TODO: Check for underlying database's existence instead of looking at in-memory stores.
func (p *Provider) GetStoreConfig(name string) ([]byte, error) {
	name = strings.ReplaceAll(strings.ToLower(name), "-", "_")

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	openStore, ok := p.dbs[name]
	if !ok {
		return []byte{}, storage.ErrStoreNotFound
	}

	storeConfigBytes, err := openStore.Get(storeConfigKey)
	if err != nil {
		return []byte{},
			fmt.Errorf(`failed to get store configuration for "%s": %w`, name, err)
	}

	return storeConfigBytes, nil
}

// GetOpenStores is currently not implemented.
func (p *Provider) GetOpenStores() []storage.Store {
	panic("not implemented")
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

	return p.db.Close()
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
	db        *sql.DB
	name      string
	tableName string
	close     closer
	lock      sync.RWMutex
}

func (s *store) Put(key string, value, tagsBytes []byte) error {
	tags := []storage.Tag{}

	if len(tagsBytes) > 0 {
		err := json.Unmarshal(tagsBytes, &tags)
		if err != nil {
			return fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}

	errInputValidation := validatePutInput(key, value, tags)
	if errInputValidation != nil {
		return errInputValidation
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

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	insertStmt := "INSERT OR REPLACE INTO " + s.tableName + " VALUES (?, ?)"
	// executing the prepared insert statement
	_, err = s.db.Exec(insertStmt, key, entryBytes, entryBytes)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingInsertStatementErrMsg, s.tableName, err)
	}

	return nil
}

func (s *store) Get(k string) ([]byte, error) {
	retrievedDBEntry, err := s.getDBEntry(k)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	return retrievedDBEntry.Value, nil
}

func (s *store) GetTags(key string) ([]byte, error) {
	retrievedDBEntry, err := s.getDBEntry(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	tagsBytes, err := json.Marshal(retrievedDBEntry.Tags)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal tags: %w", err)
	}

	return tagsBytes, nil
}

func (s *store) GetBulk(keys []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// Mobile providers doesn't currently support any of the current query options.
// pageSize will simply be ignored since it only relates to performance and not the actual end result.
func (s *store) Query(expression string, pageSize int) (api.Iterator, error) {
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
func (s *store) Delete(k string) error {
	if k == "" {
		return ErrKeyRequired
	}

	// delete query to delete the record by key
	_, err := s.db.Exec("DELETE FROM "+s.tableName+" WHERE `key`= ?", k)
	if err != nil {
		return fmt.Errorf(storage.ErrDataNotFound.Error(), err)
	}

	err = s.removeFromTagMap(k)
	if err != nil {
		return fmt.Errorf("failed to remove key from tag map: %w", err)
	}

	return nil
}

// Batch performs batch upserts and deletions preserving the batch's ordering.
// Batch is a no-op if the batch is empty.
// Batch needs both `interpolateParams` and `multiStatements` enabled in the dataSourceName
// - see the following guide: https://github.com/go-sql-driver/mysql#parameters.
// All operations in the batch are executed in a single multi-statement query due to the ordering
// requirements. This means we cannot optimize INSERT statements as per
// https://dev.mysql.com/doc/refman/8.0/en/insert-optimization.html.
// Executing a single multi-statement query requires O(N) space for the query string and an additional
// slice with O(2*N) space holding the values for the query. Callers should take care of this additional
// memory usage by limiting the size of the batch.
func (s *store) Batch(operations []byte) error { // nolint:gocyclo
	var batch []storage.Operation

	err := json.Unmarshal(operations, &batch)
	if err != nil {
		return fmt.Errorf("failed to unmarshal batch operations: %w", err)
	}

	if len(batch) == 0 {
		return errors.New("batch requires at least one operation")
	}

	var (
		query  string
		values []interface{}
	)

	for i := range batch {
		b := batch[i]

		if b.Key == "" {
			return errors.New("key cannot be empty")
		}

		err = s.bulkAppendToQuery(b, &query, &values)
		if err != nil {
			return fmt.Errorf(failureWhileExecutingBatchStatementErrMsg, s.tableName, err)
		}

		if len(b.Value) > 0 {
			err = s.updateTagMap(b.Key, b.Tags)
			if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
				return fmt.Errorf("failed to update tag map: %w", err)
			}
		} else {
			err = s.removeFromTagMap(b.Key)
			if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
				return fmt.Errorf("failed to remove key from tag map: %w", err)
			}
		}
	}

	_, err = s.db.Exec(query, values...)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingBatchStatementErrMsg, s.tableName, err)
	}

	return nil
}

func (s *store) bulkAppendToQuery(b storage.Operation, query *string, values *[]interface{}) error {
	if len(b.Value) > 0 {
		value, err := json.Marshal(dbEntry{
			Value: b.Value,
			Tags:  b.Tags,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal dbEntry: %w", err)
		}

		*query += fmt.Sprintf(
			"INSERT OR REPLACE INTO %s (`key`, `value`) VALUES (?, ?);\n",
			s.tableName,
		)

		*values = append(*values, b.Key, value)
	} else {
		*query += fmt.Sprintf("DELETE FROM %s WHERE `KEY` = ?;\n", s.tableName)
		*values = append(*values, b.Key)
	}

	return nil
}

// SQL store doesn't queue values, so there's never anything to flush.
func (s *store) Flush() error {
	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.db.Close()
	if err != nil {
		return fmt.Errorf(failureWhileClosingSQLiteConnection, err)
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

	err = s.Put(tagMapKey, tagMapBytes, []byte{})
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) getTagMap(createIfDoesNotExist bool) (tagMapping, error) {
	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		if createIfDoesNotExist && errors.Is(err, storage.ErrDataNotFound) {
			// Create the tag map if it has never been created before.
			err = s.Put(tagMapKey, []byte("{}"), []byte{})
			if err != nil {
				return nil, fmt.Errorf(`failed to create tag map for "%s": %w`, s.name, err)
			}

			tagMapBytes = []byte("{}")
		} else {
			return nil, fmt.Errorf("failed to get data: %w", err)
		}
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	return tagMap, nil
}

func (s *store) getDBEntry(key string) (dbEntry, error) {
	if key == "" {
		return dbEntry{}, ErrKeyRequired
	}

	var retrievedDBEntryBytes []byte

	// select query to fetch the record by key
	err := s.db.QueryRow("SELECT `value` FROM "+s.tableName+" "+
		" WHERE `key` = ?", key).Scan(&retrievedDBEntryBytes)
	if err != nil {
		if strings.Contains(err.Error(), valueNotFoundErrMsgFromSQlite) {
			return dbEntry{}, storage.ErrDataNotFound
		}

		return dbEntry{}, fmt.Errorf(failureWhileQueryingRowErrMsg, err)
	}

	var retrievedDBEntry dbEntry

	err = json.Unmarshal(retrievedDBEntryBytes, &retrievedDBEntry)
	if err != nil {
		return dbEntry{}, fmt.Errorf("failed to unmarshaled retrieved DB entry: %w", err)
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

	err = s.Put(tagMapKey, tagMapBytes, []byte{})
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

func (s *store) getDatabaseKeysMatchingTagNameAndValue(tagMap tagMapping, expressionTagName, expressionTagValue string,
) ([]string, error) {
	var matchingDatabaseKeys []string

	for tagName, databaseKeysSet := range tagMap {
		if tagName == expressionTagName {
			tags, err := s.getTagsMatchingTagNameAndValue(databaseKeysSet, expressionTagName, expressionTagValue)
			if err != nil {
				return nil, fmt.Errorf("failed to get tags: %w", err)
			}

			matchingDatabaseKeys = append(matchingDatabaseKeys, tags...)

			break
		}
	}

	return matchingDatabaseKeys, nil
}

func (s *store) getTagsMatchingTagNameAndValue(databaseKeysSet map[string]struct{}, expressionTagName,
	expressionTagValue string,
) ([]string, error) {
	var matchingDatabaseKeys []string

	for databaseKey := range databaseKeysSet {
		tagsBytes, err := s.GetTags(databaseKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get tags: %w", err)
		}

		tags := []storage.Tag{}

		if len(tagsBytes) > 0 {
			err = json.Unmarshal(tagsBytes, &tags)
			if err != nil {
				return []string{}, fmt.Errorf("failed to unmarshal saved tags: %w", err)
			}
		}

		for _, tag := range tags {
			if tag.Name == expressionTagName && tag.Value == expressionTagValue {
				matchingDatabaseKeys = append(matchingDatabaseKeys, databaseKey)

				break
			}
		}
	}

	return matchingDatabaseKeys, nil
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

func (i *iterator) Tags() ([]byte, error) {
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

func validatePutInput(key string, value []byte, tags []storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be empty")
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
