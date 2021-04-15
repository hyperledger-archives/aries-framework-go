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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Namespace is namespace of connection store name.
	Namespace           = "didexchange"
	keyPattern          = "%s_%s"
	connIDKeyPrefix     = "conn"
	connStateKeyPrefix  = "connstate"
	invKeyPrefix        = "inv"
	eventDataKeyPrefix  = "connevent"
	didConnMapKeyPrefix = "didconn"
	keySeparator        = "_"
	stateIDEmptyErr     = "stateID can't be empty"
)

var logger = log.New("aries-framework/store/connection")

// KeyPrefix is prefix builder for storage keys.
type KeyPrefix func(...string) string

type provider interface {
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
}

// Record contain info about did exchange connection.
type Record struct {
	ConnectionID      string
	State             string
	ThreadID          string
	ParentThreadID    string
	TheirLabel        string
	TheirDID          string
	MyDID             string
	ServiceEndPoint   string
	RecipientKeys     []string
	RoutingKeys       []string
	InvitationID      string
	InvitationDID     string
	Implicit          bool
	Namespace         string
	MediaTypeProfiles []string
}

// NewLookup returns new connection lookup instance.
// Lookup is read only connection store. It provides connection record related query features.
func NewLookup(p provider) (*Lookup, error) {
	store, err := p.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open permanent store to create new connection recorder: %w", err)
	}

	err = p.StorageProvider().SetStoreConfig(Namespace, storage.StoreConfiguration{TagNames: []string{connIDKeyPrefix}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config in permanent store: %w", err)
	}

	protocolStateStore, err := p.ProtocolStateStorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open protocol state store to create new connection recorder: %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Namespace,
		storage.StoreConfiguration{TagNames: []string{connIDKeyPrefix, connStateKeyPrefix}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config in protocol state store: %w", err)
	}

	return &Lookup{protocolStateStore: protocolStateStore, store: store}, nil
}

// Lookup takes care of connection related persistence features.
type Lookup struct {
	protocolStateStore storage.Store
	store              storage.Store
}

// GetConnectionRecord return connection record based on the connection ID.
func (c *Lookup) GetConnectionRecord(connectionID string) (*Record, error) {
	var rec Record

	err := getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.store)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			err = getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.protocolStateStore)
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
// for given query criteria.
func (c *Lookup) QueryConnectionRecords() ([]*Record, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 query criteria to be added as part of issue
	searchKey := getConnectionKeyPrefix()("")

	persistentStoreRecords, persistentStoreKeys, err := c.getDataFromPersistentStore(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from persistent store: %w", err)
	}

	allRecords, err := c.addDataFromProtocolStateStoreToRecords(searchKey, persistentStoreKeys, persistentStoreRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to augment records from persistent store with records "+
			"from the protocol state store: %w", err)
	}

	return allRecords, nil
}

func (c *Lookup) addDataFromProtocolStateStoreToRecords(searchKey string, keys map[string]struct{},
	records []*Record) ([]*Record, error) {
	protocolStateStoreItr, err := c.protocolStateStore.Query(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query protocol state store: %w", err)
	}

	defer func() {
		errClose := protocolStateStoreItr.Close()
		if errClose != nil {
			logger.Errorf("failed to close records iterator from from protocol state storage: %s", errClose.Error())
		}
	}()

	records, err = addRecordsFromProtocolStateStoreIterator(protocolStateStoreItr, keys, records)
	if err != nil {
		return nil, fmt.Errorf("failed to add records from protocol state storage iterator: %w", err)
	}

	return records, nil
}

// GetConnectionRecordAtState return connection record based on the connection ID and state.
func (c *Lookup) GetConnectionRecordAtState(connectionID, stateID string) (*Record, error) {
	if stateID == "" {
		return nil, errors.New(stateIDEmptyErr)
	}

	var rec Record

	err := getAndUnmarshal(getConnectionStateKeyPrefix()(connectionID, stateID), &rec, c.protocolStateStore)
	if err != nil {
		return nil, fmt.Errorf("faild to get connection record by state : %s, cause : %w", stateID, err)
	}

	return &rec, nil
}

// GetConnectionRecordByNSThreadID return connection record via namespaced threadID.
func (c *Lookup) GetConnectionRecordByNSThreadID(nsThreadID string) (*Record, error) {
	connectionIDBytes, err := c.protocolStateStore.Get(nsThreadID)
	if err != nil {
		return nil, fmt.Errorf("get connectionID by namespaced threadID: %w", err)
	}

	var rec Record

	err = getAndUnmarshal(getConnectionKeyPrefix()(string(connectionIDBytes)), &rec, c.protocolStateStore)
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

// GetInvitation finds and parses stored invitation to target type.
// TODO should avoid using target of type `interface{}` [Issue #1030].
func (c *Lookup) GetInvitation(id string, target interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return getAndUnmarshal(getInvitationKeyPrefix()(id), target, c.store)
}

// GetEvent returns persisted event data for given connection ID.
// TODO connection event data shouldn't be transient [Issues #1029].
func (c *Recorder) GetEvent(connectionID string) ([]byte, error) {
	if connectionID == "" {
		return nil, fmt.Errorf(errMsgInvalidKey)
	}

	return c.protocolStateStore.Get(getEventDataKeyPrefix()(connectionID))
}

func (c *Lookup) getDataFromPersistentStore(searchKey string) ([]*Record, map[string]struct{}, error) {
	itr, errQuery := c.store.Query(searchKey)
	if errQuery != nil {
		return nil, nil, fmt.Errorf("failed to query permanent store: %w", errQuery)
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close records iterator from permanent storage: %s", errClose.Error())
		}
	}()

	var records []*Record

	keys := make(map[string]struct{})

	more, errNext := itr.Next()
	if errNext != nil {
		return nil, nil, fmt.Errorf("failed to get next set of data from permanent storage iterator: %w", errNext)
	}

	for more {
		value, err := itr.Value()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		var record Record

		err = json.Unmarshal(value, &record)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal connection record: %w", err)
		}

		key, err := itr.Key()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get key from iterator: %w", err)
		}

		keys[key] = struct{}{}

		records = append(records, &record)

		more, err = itr.Next()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get next set of data from permanent storage iterator: %w", err)
		}
	}

	return records, keys, nil
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

// getConnectionKeyPrefix key prefix for connection record persisted.
func getConnectionKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connIDKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getConnectionStateKeyPrefix key prefix for state based connection record persisted.
func getConnectionStateKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, connStateKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getInvitationKeyPrefix key prefix for saving invitations.
func getInvitationKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, invKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getNamespaceKeyPrefix key prefix for saving connections records with mappings.
func getNamespaceKeyPrefix(prefix string) KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, prefix, strings.Join(key, keySeparator))
	}
}

// getEventDataKeyPrefix key prefix for saving event data.
func getEventDataKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, eventDataKeyPrefix, strings.Join(key, keySeparator))
	}
}

// getDIDConnMapKeyPrefix key prefix for saving mapping between DID and ConnectionID.
func getDIDConnMapKeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, didConnMapKeyPrefix, strings.Join(key, keySeparator))
	}
}

// CreateNamespaceKey creates key prefix for namespace related data.
func CreateNamespaceKey(prefix, thID string) (string, error) {
	key, err := computeHash([]byte(thID))
	if err != nil {
		return "", err
	}

	return getNamespaceKeyPrefix(prefix)(key), nil
}

func addRecordsFromProtocolStateStoreIterator(protocolStateStoreItr storage.Iterator, keys map[string]struct{},
	records []*Record) ([]*Record, error) {
	more, err := protocolStateStoreItr.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next set of data from protocol state store iterator: %w", err)
	}

	for more {
		key, err := protocolStateStoreItr.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get key from iterator: %w", err)
		}

		// don't fetch data from protocol state store if same record is present in permanent store
		if _, ok := keys[key]; ok {
			more, err = protocolStateStoreItr.Next()
			if err != nil {
				return nil, fmt.Errorf("failed to get next set of data from protocol state store iterator: %w", err)
			}

			continue
		}

		value, err := protocolStateStoreItr.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		var record Record

		if errUnmarshal := json.Unmarshal(value, &record); errUnmarshal != nil {
			return nil, fmt.Errorf("query connection records from protocol state store : %w", errUnmarshal)
		}

		records = append(records, &record)

		more, err = protocolStateStoreItr.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next set of data from protocol state store iterator: %w", err)
		}
	}

	return records, nil
}
