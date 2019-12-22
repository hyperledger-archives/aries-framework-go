/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package connectionstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	nameSpace          = "didexchange"
	keyPattern         = "%s_%s"
	connIDKeyPrefix    = "conn"
	connStateKeyPrefix = "connstate"
	// limitPattern with `~` at the end for lte of given prefix (less than or equal)
	limitPattern    = "%s~"
	keySeparator    = "_"
	stateIDEmptyErr = "stateID can't be empty"
)

// KeyPrefix is prefix builder for storage keys
type KeyPrefix func(...string) string

type provider interface {
	TransientStorageProvider() storage.Provider
	StorageProvider() storage.Provider
}

// ConnectionRecord contain info about did exchange connection
type ConnectionRecord struct {
	ConnectionID    string
	State           string
	ThreadID        string
	TheirLabel      string
	TheirDID        string
	MyDID           string
	ServiceEndPoint string
	RecipientKeys   []string
	InvitationID    string
	InvitationDID   string
	Implicit        bool
	Namespace       string
}

// NewConnectionLookup returns new connection recorder instance
func NewConnectionLookup(p provider) (*ConnectionLookup, error) {
	store, err := p.StorageProvider().OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open permanent store to create new connection recorder: %w", err)
	}

	transientStore, err := p.TransientStorageProvider().OpenStore(nameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open transient store to create new connection recorder: %w", err)
	}

	return &ConnectionLookup{transientStore: transientStore, store: store}, nil
}

// ConnectionLookup takes care of connection related persistence features
type ConnectionLookup struct {
	transientStore storage.Store
	store          storage.Store
}

// GetConnectionRecord return connection record based on the connection ID
func (c *ConnectionLookup) GetConnectionRecord(connectionID string) (*ConnectionRecord, error) {
	rec, err := getAndUnmarshal(GetConnectionKeyPrefix()(connectionID), c.store)
	if errors.Is(err, storage.ErrDataNotFound) {
		return getAndUnmarshal(GetConnectionKeyPrefix()(connectionID), c.transientStore)
	}

	return rec, err
}

// QueryConnectionRecords returns connection records found in underlying store
// for given query criteria
func (c *ConnectionLookup) QueryConnectionRecords() ([]*ConnectionRecord, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 query criteria to be added as part of issue
	searchKey := GetConnectionKeyPrefix()("")

	itr := c.store.Iterator(searchKey, fmt.Sprintf(limitPattern, searchKey))
	defer itr.Release()

	var records []*ConnectionRecord

	keys := make(map[string]struct{})

	for itr.Next() {
		var record ConnectionRecord

		err := json.Unmarshal(itr.Value(), &record)
		if err != nil {
			return nil, fmt.Errorf("failed to query connection records, %w", err)
		}

		keys[string(itr.Key())] = struct{}{}

		records = append(records, &record)
	}

	transientItr := c.transientStore.Iterator(searchKey, fmt.Sprintf(limitPattern, searchKey))
	defer transientItr.Release()

	for transientItr.Next() {
		// don't fetch data from transient store if same record is present in permanent store
		if _, ok := keys[string(transientItr.Key())]; ok {
			continue
		}

		var record ConnectionRecord

		if err := json.Unmarshal(transientItr.Value(), &record); err != nil {
			return nil, fmt.Errorf("query connection records from transient store : %w", err)
		}

		records = append(records, &record)
	}

	return records, nil
}

// GetConnectionRecordAtState return connection record based on the connection ID and state.
func (c *ConnectionLookup) GetConnectionRecordAtState(connectionID, stateID string) (*ConnectionRecord, error) {
	if stateID == "" {
		return nil, errors.New(stateIDEmptyErr)
	}

	return getAndUnmarshal(GetConnectionStateKeyPrefix()(connectionID, stateID), c.transientStore)
}

func getAndUnmarshal(k string, store storage.Store) (*ConnectionRecord, error) {
	connRecordBytes, err := store.Get(k)
	if err != nil {
		return nil, err
	}

	return prepareConnectionRecord(connRecordBytes)
}

// GetConnectionRecordByNSThreadID return connection record via namespaced threadID
func (c *ConnectionLookup) GetConnectionRecordByNSThreadID(nsThreadID string) (*ConnectionRecord, error) {
	connectionIDBytes, err := c.transientStore.Get(nsThreadID)
	if err != nil {
		return nil, fmt.Errorf("get connectionID by namespaced threadID: %w", err)
	}
	// adding prefix for storing connection record
	k := GetConnectionKeyPrefix()(string(connectionIDBytes))

	connRecordBytes, err := c.transientStore.Get(k)
	if err != nil {
		return nil, fmt.Errorf("get connection record by connectionID: %w", err)
	}

	return prepareConnectionRecord(connRecordBytes)
}

// Store returns handle to underlying permanent store
func (c *ConnectionLookup) Store() storage.Store {
	return c.store
}

// TransientStore returns handle to underlying transient store
func (c *ConnectionLookup) TransientStore() storage.Store {
	return c.transientStore
}

// GetConnectionKeyPrefix key prefix for connection record persisted
func GetConnectionKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connIDKeyPrefix, strings.Join(key, keySeparator))
	}
}

// GetConnectionStateKeyPrefix key prefix for state based connection record persisted
func GetConnectionStateKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connStateKeyPrefix, strings.Join(key, keySeparator))
	}
}

func prepareConnectionRecord(connRecBytes []byte) (*ConnectionRecord, error) {
	connRecord := &ConnectionRecord{}

	err := json.Unmarshal(connRecBytes, connRecord)
	if err != nil {
		return nil, fmt.Errorf("prepare connection record: %w", err)
	}

	return connRecord, nil
}
