/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Namespace is namespace of connection store name
	Namespace           = "didexchange"
	keyPattern          = "%s_%s"
	connIDKeyPrefix     = "conn"
	connStateKeyPrefix  = "connstate"
	invKeyPrefix        = "inv"
	eventDataKeyPrefix  = "connevent"
	didConnMapKeyPrefix = "didconn"
	// limitPattern with `~` at the end for lte of given prefix (less than or equal)
	limitPattern    = "%s" + storage.EndKeySuffix
	keySeparator    = "_"
	stateIDEmptyErr = "stateID can't be empty"
)

// KeyPrefix is prefix builder for storage keys
type KeyPrefix func(...string) string

type provider interface {
	TransientStorageProvider() storage.Provider
	StorageProvider() storage.Provider
}

// Record contain info about did exchange connection
type Record struct {
	ConnectionID    string
	State           string
	ThreadID        string
	ParentThreadID  string
	TheirLabel      string
	TheirDID        string
	MyDID           string
	ServiceEndPoint string
	RecipientKeys   []string
	RoutingKeys     []string
	InvitationID    string
	InvitationDID   string
	Implicit        bool
	Namespace       string
}

// NewLookup returns new connection lookup instance.
// Lookup is read only connection store. It provides connection record related query features.
func NewLookup(p provider) (*Lookup, error) {
	store, err := p.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open permanent store to create new connection recorder: %w", err)
	}

	transientStore, err := p.TransientStorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open transient store to create new connection recorder: %w", err)
	}

	return &Lookup{transientStore: transientStore, store: store}, nil
}

// Lookup takes care of connection related persistence features
type Lookup struct {
	transientStore storage.Store
	store          storage.Store
}

// GetConnectionRecord return connection record based on the connection ID
func (c *Lookup) GetConnectionRecord(connectionID string) (*Record, error) {
	var rec Record

	err := getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.store)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			err = getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.transientStore)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return &rec, nil
}

// QueryConnectionRecords returns connection records found in underlying store
// for given query criteria
func (c *Lookup) QueryConnectionRecords() ([]*Record, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 query criteria to be added as part of issue
	searchKey := getConnectionKeyPrefix()("")

	itr := c.store.Iterator(searchKey, fmt.Sprintf(limitPattern, searchKey))
	defer itr.Release()

	var records []*Record

	keys := make(map[string]struct{})

	for itr.Next() {
		var record Record

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

		var record Record

		if err := json.Unmarshal(transientItr.Value(), &record); err != nil {
			return nil, fmt.Errorf("query connection records from transient store : %w", err)
		}

		records = append(records, &record)
	}

	return records, nil
}

// GetConnectionRecordAtState return connection record based on the connection ID and state.
func (c *Lookup) GetConnectionRecordAtState(connectionID, stateID string) (*Record, error) {
	if stateID == "" {
		return nil, errors.New(stateIDEmptyErr)
	}

	var rec Record

	err := getAndUnmarshal(getConnectionStateKeyPrefix()(connectionID, stateID), &rec, c.transientStore)
	if err != nil {
		return nil, fmt.Errorf("faild to get connection record by state : %s, cause : %w", stateID, err)
	}

	return &rec, nil
}

// GetConnectionRecordByNSThreadID return connection record via namespaced threadID
func (c *Lookup) GetConnectionRecordByNSThreadID(nsThreadID string) (*Record, error) {
	connectionIDBytes, err := c.transientStore.Get(nsThreadID)
	if err != nil {
		return nil, fmt.Errorf("get connectionID by namespaced threadID: %w", err)
	}

	var rec Record

	err = getAndUnmarshal(getConnectionKeyPrefix()(string(connectionIDBytes)), &rec, c.transientStore)
	if err != nil {
		return nil, fmt.Errorf("faild to get connection record by NS thread ID : %s, cause : %w", nsThreadID, err)
	}

	return &rec, nil
}

// GetConnectionIDByDIDs return connection id based on dids (my or their did) metadata.
func (c *Lookup) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	connectionIDBytes, err := c.store.Get(getDIDConnMapKeyPrefix()(myDID, theirDID))
	if err != nil {
		return "", fmt.Errorf("get did-connection map : %w", err)
	}

	return string(connectionIDBytes), nil
}

// GetInvitation finds and parses stored invitation to target type
// TODO should avoid using target of type `interface{}` [Issue #1030]
func (c *Lookup) GetInvitation(id string, target interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return getAndUnmarshal(getInvitationKeyPrefix()(id), target, c.store)
}

// GetEvent returns persisted event data for given connection ID
// TODO connection event data shouldn't be transient [Issues #1029]
func (c *Recorder) GetEvent(connectionID string) ([]byte, error) {
	if connectionID == "" {
		return nil, fmt.Errorf(errMsgInvalidKey)
	}

	return c.transientStore.Get(getEventDataKeyPrefix()(connectionID))
}

func getAndUnmarshal(key string, target interface{}, store storage.Store) error {
	bytes, err := store.Get(key)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, target)
	if err != nil {
		return err
	}

	return nil
}

// getConnectionKeyPrefix key prefix for connection record persisted
func getConnectionKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connIDKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getConnectionStateKeyPrefix key prefix for state based connection record persisted
func getConnectionStateKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connStateKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getInvitationKeyPrefix key prefix for saving invitations
func getInvitationKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, invKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getNamespaceKeyPrefix key prefix for saving connections records with mappings
func getNamespaceKeyPrefix(prefix string) KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, prefix, strings.Join(key, keySeparator))
	}
}

// getEventDataKeyPrefix key prefix for saving event data
func getEventDataKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, eventDataKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getDIDConnMapKeyPrefix key prefix for saving mapping between DID and ConnectionID
func getDIDConnMapKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, didConnMapKeyPrefix, strings.Join(key, keySeparator))
	}
}

// CreateNamespaceKey creates key prefix for namespace related data
func CreateNamespaceKey(prefix, thID string) (string, error) {
	key, err := computeHash([]byte(thID))
	if err != nil {
		return "", err
	}

	return getNamespaceKeyPrefix(prefix)(key), nil
}
