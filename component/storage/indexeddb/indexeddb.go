// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indexeddb

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// TODO (#2528): Proper implementation of all methods.

const (
	dbName                          = "aries-%s"
	defDBName                       = "aries"
	dbVersion                       = 1
	tagMapKey                       = "TagMap"
	storeConfigKey                  = "StoreConfig"
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`

	invalidQueryExpressionFormat = `"%s" is not in a valid expression format. ` +
		"it must be in the following format: TagName:TagValue"
)

// TODO (#2540): Use proper IndexedDB indexing instead of the "Tag Map" once aries-framework-go is updated to use the
// new storage interface. The tag names used in the predefined stores (see getStoreNames()) will need to be passed in
// somehow.
type tagMapping map[string]map[string]struct{} // map[TagName](Set of database Keys)

// Provider is an IndexedDB implementation of the storage.Provider interface.
type Provider struct {
	stores map[string]*store
	lock   sync.RWMutex
}

// NewProvider instantiates a new IndexedDB provider.
func NewProvider(name string) (*Provider, error) {
	p := &Provider{stores: make(map[string]*store)}

	db := defDBName
	if name != "" {
		db = fmt.Sprintf(dbName, name)
	}

	err := p.openDB(db, getStoreNames()...)
	if err != nil {
		return nil, fmt.Errorf("failed to open IndexDB : %w", err)
	}

	return p, nil
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	name = strings.ToLower(name)

	p.lock.RLock()
	openStore, ok := p.stores[name]
	p.lock.RUnlock()

	if ok {
		return openStore, nil
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	// create new if not found in list of object stores (not the predefined ones)
	err := p.openDB(fmt.Sprintf(dbName, name), name)
	if err != nil {
		return nil, err
	}

	return p.stores[name], nil
}

// SetStoreConfig sets the configuration on a store.
// With the current implementation, this does not need to be called in order to use tags and querying.
// For consistency with other storage implementations, the store configuration is still stored (but it otherwise serves
// no purpose).
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	store, ok := p.stores[name]
	if !ok {
		return storage.ErrStoreNotFound
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal store configuration: %w", err)
	}

	err = store.Put(storeConfigKey, configBytes)
	if err != nil {
		return fmt.Errorf("failed to put store configuration: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	store, ok := p.stores[name]
	if !ok {
		return storage.StoreConfiguration{}, storage.ErrStoreNotFound
	}

	storeConfigBytes, err := store.Get(storeConfigKey)
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

// GetOpenStores is currently not implemented (TODO #2528).
func (p *Provider) GetOpenStores() []storage.Store {
	return nil
}

// Close closes all stores created under this store provider.
// There's nothing to do here, so it always returns nil.
func (p *Provider) Close() error {
	return nil
}

func (p *Provider) openDB(db string, names ...string) error {
	req := js.Global().Get("indexedDB").Call("open", db, dbVersion)
	req.Set("onupgradeneeded", js.FuncOf(func(this js.Value, inputs []js.Value) interface{} {
		m := make(map[string]interface{})
		m["keyPath"] = "key"
		for _, name := range names {
			this.Get("result").Call("createObjectStore", name, m)
		}
		return nil
	}))

	v, err := getResult(req)
	if err != nil {
		return fmt.Errorf("failed to open indexedDB: %w", err)
	}

	for _, name := range names {
		newStore := &store{name: name, db: v}

		// Create the tag map if it doesn't exist already.
		_, err = newStore.Get(tagMapKey)
		if errors.Is(err, storage.ErrDataNotFound) {
			err = newStore.Put(tagMapKey, []byte("{}"))
			if err != nil {
				return fmt.Errorf(`failed to create tag map for "%s": %w`, name, err)
			}
		} else if err != nil {
			return fmt.Errorf("unexpected failure while getting tag data bytes: %w", err)
		}

		p.stores[name] = newStore
	}

	return nil
}

type store struct {
	name string
	db   *js.Value
}

func (s *store) Put(key string, value []byte, tags ...storage.Tag) error {
	if key == "" || value == nil {
		return errors.New("key and value are mandatory")
	}

	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	m := make(map[string]interface{})
	m["key"] = key

	m["value"] = base64.StdEncoding.EncodeToString(value)

	if len(tags) > 0 {
		tagsBytes, err := json.Marshal(tags)
		if err != nil {
			return fmt.Errorf("failed to marshal tags: %w", err)
		}

		m["tags"] = string(tagsBytes)

		err = s.updateTagMap(key, tags)
		if err != nil {
			return fmt.Errorf("failed to update tag map: %w", err)
		}
	}

	req := s.db.Call("transaction", s.name, "readwrite").Call("objectStore", s.name).Call("put", m)

	_, err := getResult(req)
	if err != nil {
		return fmt.Errorf("failed to store data: %w", err)
	}

	return nil
}

func (s *store) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("key is mandatory")
	}

	req := s.db.Call("transaction", s.name).Call("objectStore", s.name).Call("get", key)

	data, err := getResult(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	if !data.Truthy() {
		return nil, storage.ErrDataNotFound
	}

	valueBase64Encoded := data.Get("value").String()

	value, err := base64.StdEncoding.DecodeString(valueBase64Encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode the store value: %w", err)
	}

	return value, nil
}

func (s *store) GetTags(key string) ([]storage.Tag, error) {
	if key == "" {
		return nil, errors.New("key is mandatory")
	}

	req := s.db.Call("transaction", s.name).Call("objectStore", s.name).Call("get", key)

	data, err := getResult(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}

	if !data.Truthy() {
		return nil, storage.ErrDataNotFound
	}

	tagsBytes := []byte(data.Get("tags").String())

	var tags []storage.Tag

	err = json.Unmarshal(tagsBytes, &tags)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags bytes: %w", err)
	}

	return tags, nil
}

// Currently not implemented (TODO #2528).
func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	if expression == "" {
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}

	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get tag map: %w", err)
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		matchingDatabaseKeys := getDatabaseKeysMatchingTagName(tagMap, expressionTagName)

		return &iterator{keys: matchingDatabaseKeys, store: s}, nil
	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		matchingDatabaseKeys, err :=
			s.getDatabaseKeysMatchingTagNameAndValue(tagMap, expressionTagName, expressionTagValue)
		if err != nil {
			return nil, fmt.Errorf("failed to get database keys matching tag name and value: %w", err)
		}

		return &iterator{keys: matchingDatabaseKeys, store: s}, nil
	default:
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}
}

// Delete will delete record with k key.
func (s *store) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	req := s.db.Call("transaction", s.name, "readwrite").Call("objectStore", s.name).Call("delete", k)

	_, err := getResult(req)
	if err != nil {
		return fmt.Errorf("failed to delete data with key: %s - error: %w", k, err)
	}

	err = s.removeFromTagMap(k)
	if err != nil {
		return fmt.Errorf("failed to remove key from tag map: %w", err)
	}

	return nil
}

func (s *store) Batch(operations []storage.Operation) error {
	for _, operation := range operations {
		if operation.Value == nil {
			err := s.Delete(operation.Key)
			if err != nil {
				return fmt.Errorf("failed to delete: %w", err)
			}
		} else {
			err := s.Put(operation.Key, operation.Value, operation.Tags...)
			if err != nil {
				return fmt.Errorf("failed to put: %w", err)
			}
		}
	}

	return nil
}

// This store doesn't queue values, so there's never anything to flush.
func (s *store) Flush() error {
	return nil
}

// Nothing to close, so this always returns nil.
func (s *store) Close() error {
	return nil
}

func (s *store) updateTagMap(key string, tags []storage.Tag) error {
	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		return fmt.Errorf("failed to get tag map: %w", err)
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	for _, tag := range tags {
		if tagMap[tag.Name] == nil {
			tagMap[tag.Name] = make(map[string]struct{})
		}

		tagMap[tag.Name][key] = struct{}{}
	}

	tagMapBytes, err = json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) removeFromTagMap(keyToRemove string) error {
	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		// If there's no tag map, then this means that no store configuration was set.
		// Nothing needs to be done in this case, as it means that this store doesn't use tags.
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil
		}

		return fmt.Errorf("failed to get tag map: %w", err)
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	for _, tagNameToKeys := range tagMap {
		delete(tagNameToKeys, keyToRemove)
	}

	tagMapBytes, err = json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
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
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	return tags, nil
}

func (i *iterator) Close() error {
	return nil
}

func getResult(req js.Value) (*js.Value, error) {
	onsuccess := make(chan js.Value)
	onerror := make(chan js.Value)

	const timeout = 10

	req.Set("onsuccess", js.FuncOf(func(this js.Value, inputs []js.Value) interface{} {
		onsuccess <- this.Get("result")
		return nil
	}))
	req.Set("onerror", js.FuncOf(func(this js.Value, inputs []js.Value) interface{} {
		onerror <- this.Get("error")
		return nil
	}))
	select {
	case value := <-onsuccess:
		return &value, nil
	case value := <-onerror:
		return nil, fmt.Errorf("%s %s", value.Get("name").String(),
			value.Get("message").String())
	case <-time.After(timeout * time.Second):
		return nil, errors.New("timeout waiting for eve")
	}
}

// since IndexedDB doesn't support adding object stores on the fly, using predefined object store names to
// create object store in advance instead of creating a database per store.
// TODO pass store names from higher level packages during initialization [Issue #1347].
func getStoreNames() []string {
	return []string{
		strings.ToLower(messenger.MessengerStore),
		strings.ToLower(mediator.Coordination),
		strings.ToLower(connection.Namespace),
		strings.ToLower(introduce.Introduce),
		strings.ToLower(peer.StoreNamespace),
		strings.ToLower(did.StoreName),
		strings.ToLower(localkms.Namespace),
		strings.ToLower(verifiable.NameSpace),
		strings.ToLower(issuecredential.Name),
		strings.ToLower(presentproof.Name),
	}
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
