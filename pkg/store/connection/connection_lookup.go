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
	didcomm "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Namespace is namespace of connection store name.
	Namespace          = "didexchange"
	keyPattern         = "%s_%s"
	connIDKeyPrefix    = "conn"
	connStateKeyPrefix = "connstate"
	bothDIDsTagName    = "bothDIDs"
	theirDIDTagName    = "theirDID"
	invKeyPrefix       = "inv"
	oobV2InvKeyPrefix  = "oob2"
	eventDataKeyPrefix = "connevent"
	keySeparator       = "_"
	stateIDEmptyErr    = "stateID can't be empty"
)

var logger = log.New("aries-framework/store/connection")

// KeyPrefix is prefix builder for storage keys.
type KeyPrefix func(...string) string

type provider interface {
	ProtocolStateStorageProvider() storage.Provider
	StorageProvider() storage.Provider
}

// DIDRotationRecord holds information about a DID Rotation.
type DIDRotationRecord struct {
	OldDID    string `json:"oldDID,omitempty"`
	NewDID    string `json:"newDID,omitempty"`
	FromPrior string `json:"fromPrior,omitempty"`
}

// Record contain info about did exchange connection.
type Record struct {
	ConnectionID        string
	State               string
	ThreadID            string
	ParentThreadID      string
	TheirLabel          string
	TheirDID            string
	MyDID               string
	ServiceEndPoint     string   // ServiceEndPoint is 'their' DIDComm service endpoint.
	RecipientKeys       []string // RecipientKeys holds 'their' DIDComm recipient keys.
	RoutingKeys         []string // RoutingKeys holds 'their' DIDComm routing keys.
	InvitationID        string
	InvitationDID       string
	Implicit            bool
	Namespace           string
	MediaTypeProfiles   []string
	DIDCommVersion      didcomm.Version
	PeerDIDInitialState string
	MyDIDRotation       *DIDRotationRecord `json:"myDIDRotation,omitempty"`
}

// NewLookup returns new connection lookup instance.
// Lookup is read only connection store. It provides connection record related query features.
func NewLookup(p provider) (*Lookup, error) {
	store, err := p.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open permanent store to create new connection recorder: %w", err)
	}

	err = p.StorageProvider().SetStoreConfig(Namespace, storage.StoreConfiguration{TagNames: []string{
		connIDKeyPrefix,
		bothDIDsTagName,
		theirDIDTagName,
	}})
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

// GetConnectionRecordByDIDs return connection record for completed connection based on the DIDs of the participants.
func (c *Lookup) GetConnectionRecordByDIDs(myDID, theirDID string) (*Record, error) {
	return c.queryExpectingOne(bothDIDsTagName+":"+tagValueFromDIDs(myDID, theirDID), c.store)
}

// GetConnectionRecordByTheirDID return connection record for completed connection based on the DID of the other party.
func (c *Lookup) GetConnectionRecordByTheirDID(theirDID string) (*Record, error) {
	return c.queryExpectingOne(theirDIDTagName+":"+tagValueFromDIDs(theirDID), c.store)
}

func (c *Lookup) queryExpectingOne(query string, store storage.Store) (*Record, error) {
	records, err := queryRecordsFromStore(query, store, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from persistent store: %w", err)
	}

	if len(records) == 0 {
		return nil, storage.ErrDataNotFound
	}

	logger.Debugf("query '%s' expected 1 result, got %d", query, len(records))

	return records[0], nil
}

// QueryConnectionRecords returns connection records found in underlying store
// for given query criteria.
func (c *Lookup) QueryConnectionRecords() ([]*Record, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 query criteria to be added as part of issue
	searchKey := getConnectionKeyPrefix()("")

	var (
		records []*Record
		keys    = make(map[string]struct{})
		err     error
	)

	records, err = queryRecordsFromStore(searchKey, c.store, keys, records)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from persistent store: %w", err)
	}

	records, err = queryRecordsFromStore(searchKey, c.protocolStateStore, keys, records)
	if err != nil {
		return nil, fmt.Errorf("failed to augment records from persistent store with records "+
			"from the protocol state store: %w", err)
	}

	return records, nil
}

func queryRecordsFromStore(searchKey string, store storage.Store, usedKeys map[string]struct{}, appendTo []*Record) (
	[]*Record, error) {
	if usedKeys == nil {
		usedKeys = make(map[string]struct{})
	}

	itr, err := store.Query(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close records iterator: %s", errClose.Error())
		}
	}()

	appendTo, err = readRecordIterator(itr, usedKeys, appendTo)
	if err != nil {
		return nil, fmt.Errorf("failed to read records: %w", err)
	}

	return appendTo, nil
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
	record, err := c.GetConnectionRecordByDIDs(myDID, theirDID)
	if err != nil {
		return "", fmt.Errorf("get connection record by DIDs: %w", err)
	}

	return record.ConnectionID, nil
}

// GetInvitation finds and parses stored invitation to target type.
// TODO should avoid using target of type `interface{}` [Issue #1030].
func (c *Lookup) GetInvitation(id string, target interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return getAndUnmarshal(getInvitationKeyPrefix()(id), target, c.store)
}

// GetOOBv2Invitation finds and parses stored OOBv2 invitation to target type.
// TODO should avoid using target of type `interface{}` [Issue #1030].
func (c *Lookup) GetOOBv2Invitation(myDID string, target interface{}) error {
	if myDID == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return getAndUnmarshal(getOOBInvitationV2KeyPrefix()(tagValueFromDIDs(myDID)), target, c.store)
}

// GetEvent returns persisted event data for given connection ID.
// TODO connection event data shouldn't be transient [Issues #1029].
func (c *Recorder) GetEvent(connectionID string) ([]byte, error) {
	if connectionID == "" {
		return nil, fmt.Errorf(errMsgInvalidKey)
	}

	return c.protocolStateStore.Get(getEventDataKeyPrefix()(connectionID))
}

func readRecordIterator(itr storage.Iterator, usedKeys map[string]struct{}, appendTo []*Record) ([]*Record, error) {
	var (
		more    bool
		errNext error
	)

	for more, errNext = itr.Next(); more && errNext == nil; more, errNext = itr.Next() {
		key, err := itr.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get key from iterator: %w", err)
		}

		// skip elements that were already found in a previous store
		if _, ok := usedKeys[key]; ok {
			continue
		}

		value, err := itr.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		var record Record

		err = json.Unmarshal(value, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal connection record: %w", err)
		}

		appendTo = append(appendTo, &record)
		usedKeys[key] = struct{}{}
	}

	if errNext != nil {
		return nil, fmt.Errorf("failed to get next set of data from iterator: %w", errNext)
	}

	return appendTo, nil
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

// getOOBInvitationV2KeyPrefix key prefix for saving OOBv2 invitations.
func getOOBInvitationV2KeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, oobV2InvKeyPrefix, strings.Join(key, keySeparator))
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

// CreateNamespaceKey creates key prefix for namespace related data.
func CreateNamespaceKey(prefix, thID string) (string, error) {
	key, err := computeHash([]byte(thID))
	if err != nil {
		return "", err
	}

	return getNamespaceKeyPrefix(prefix)(key), nil
}

func tagValueFromDIDs(dids ...string) string {
	// DIDs have colons, but tag values can't, so we replace each colon with a $
	for i, did := range dids {
		dids[i] = strings.ReplaceAll(did, ":", "$")
	}

	return strings.Join(dids, "|")
}
