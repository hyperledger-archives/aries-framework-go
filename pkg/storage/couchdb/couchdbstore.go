// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"

	_ "github.com/go-kivik/couchdb" // The CouchDB driver
	"github.com/go-kivik/kivik"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider represents an CouchDB implementation of the storage.Provider interface
type Provider struct {
	hostURL       string
	couchDBClient *kivik.Client
	dbs           map[string]*CouchDBStore
	sync.RWMutex
}

const (
	blankHostErrMsg           = "hostURL for new CouchDB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
)

// NewProvider instantiates Provider
func NewProvider(hostURL string) (*Provider, error) {
	if hostURL == "" {
		return nil, errors.New(blankHostErrMsg)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, err
	}

	return &Provider{hostURL: hostURL, couchDBClient: client, dbs: map[string]*CouchDBStore{}}, nil
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.Lock()
	defer p.Unlock()

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	dbExists, err := p.couchDBClient.DBExists(context.Background(), name)
	if err != nil {
		return nil, fmt.Errorf("failed to check db exists: %w", err)
	}

	if !dbExists {
		err := p.couchDBClient.CreateDB(context.Background(), name)
		if err != nil {
			return nil, fmt.Errorf("failed to create db: %w", err)
		}
	}

	db := p.couchDBClient.DB(context.Background(), name)

	if db.Err() != nil {
		return nil, db.Err()
	}

	store := &CouchDBStore{db: db, revIDs: make(map[string]string)}

	p.dbs[name] = store

	return store, nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.Lock()
	defer p.Unlock()

	store, exists := p.dbs[name]
	if !exists {
		return nil
	}

	delete(p.dbs, name)

	return store.db.Close(context.Background())
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.Lock()
	defer p.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close(context.Background())
		if err != nil {
			return fmt.Errorf(failToCloseProviderErrMsg+": %w", err)
		}
	}

	if err := p.couchDBClient.Close(context.Background()); err != nil {
		return err
	}

	p.dbs = make(map[string]*CouchDBStore)

	return nil
}

// CouchDBStore represents a CouchDB-backed database.
type CouchDBStore struct {
	db *kivik.DB
	// TODO change to leveldb https://github.com/hyperledger/aries-framework-go/issues/1608
	revIDs map[string]string
}

// Put stores the given key-value pair in the store.
func (c *CouchDBStore) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	var valueToPut []byte
	if isJSON(v) {
		valueToPut = v
	} else {
		valueToPut = wrapTextAsCouchDBAttachment(v)
	}

	if c.revIDs[k] != "" {
		var m map[string]interface{}
		if err := json.Unmarshal(valueToPut, &m); err != nil {
			return fmt.Errorf("failed to unmarshal put value: %w", err)
		}

		m["_rev"] = c.revIDs[k]

		var err error
		valueToPut, err = json.Marshal(m)

		if err != nil {
			return fmt.Errorf("failed to marshal put value: %w", err)
		}
	}

	rev, err := c.db.Put(context.Background(), k, valueToPut)
	if err != nil {
		return fmt.Errorf("failed to store data: %w", err)
	}

	c.revIDs[k] = rev

	return nil
}

func isJSON(textToCheck []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(textToCheck, &js) == nil
}

// Kivik has a PutAttachment method, but it requires creating a document first and then adding an attachment after.
// We want to do it all in one step, hence this manual stuff below.
func wrapTextAsCouchDBAttachment(textToWrap []byte) []byte {
	encodedTextToWrap := base64.StdEncoding.EncodeToString(textToWrap)
	return []byte(`{"_attachments": {"data": {"data": "` + encodedTextToWrap + `", "content_type": "text/plain"}}}`)
}

// Get retrieves the value in the store associated with the given key.
func (c *CouchDBStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), "Not Found:") {
			return nil, storage.ErrDataNotFound
		}

		return nil, err
	}

	return c.getStoredValueFromRawDoc(rawDoc, k)
}

// Delete will delete record with k key
func (c *CouchDBStore) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	_, err := c.db.Delete(context.TODO(), k, c.revIDs[k])
	if err != nil {
		return fmt.Errorf("failed to delete doc: %w", err)
	}

	return nil
}

// Iterator returns iterator for the latest snapshot of the underlying db.
func (c *CouchDBStore) Iterator(startKey, endKey string) storage.StoreIterator {
	resultRows, err := c.db.AllDocs(context.TODO(), kivik.Options{
		"startkey":      startKey,
		"endkey":        strings.ReplaceAll(endKey, storage.EndKeySuffix, kivik.EndKeySuffix),
		"inclusive_end": "false", // endkey should be exclusive to be consistent with goleveldb
		"include_docs":  "true",
	})
	if err != nil {
		return &couchDBResultsIterator{store: c, resultRows: &kivik.Rows{},
			err: fmt.Errorf("failed to query docs: %w", err)}
	}

	return &couchDBResultsIterator{store: c, resultRows: resultRows}
}

type couchDBResultsIterator struct {
	store      *CouchDBStore
	resultRows *kivik.Rows
	err        error
}

func (i *couchDBResultsIterator) Next() bool {
	return i.resultRows.Next()
}

func (i *couchDBResultsIterator) Release() {
	if err := i.resultRows.Close(); err != nil {
		i.err = err
	}
}

func (i *couchDBResultsIterator) Error() error {
	if i.err != nil {
		return i.err
	}

	return i.resultRows.Err()
}

// Key returns the key of the current key-value pair.
func (i *couchDBResultsIterator) Key() []byte {
	key := i.resultRows.Key()
	if key != "" {
		// The returned key is a raw JSON string. It needs to be unescaped:
		v, err := strconv.Unquote(key)
		if err != nil {
			i.err = err
			return nil
		}

		return []byte(v)
	}

	return nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() []byte {
	rawDoc := make(map[string]interface{})

	err := i.resultRows.ScanDoc(&rawDoc)

	if err != nil {
		i.err = err
		return nil
	}

	key := i.Key()

	v, err := i.store.getStoredValueFromRawDoc(rawDoc, string(key))
	if err != nil {
		i.err = err

		return nil
	}

	return v
}

func (c *CouchDBStore) getStoredValueFromRawDoc(rawDoc map[string]interface{}, k string) ([]byte, error) {
	_, containsAttachment := rawDoc["_attachments"]
	if containsAttachment {
		return c.getDataFromAttachment(k)
	}

	// Strip out the CouchDB-specific fields
	delete(rawDoc, "_id")
	delete(rawDoc, "_rev")

	strippedJSON, err := json.Marshal(rawDoc)
	if err != nil {
		return nil, err
	}

	return strippedJSON, nil
}

func (c *CouchDBStore) getDataFromAttachment(k string) ([]byte, error) {
	attachment, err := c.db.GetAttachment(context.Background(), k, "data")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(attachment.Content)
	if err != nil {
		return nil, err
	}

	return data, nil
}
