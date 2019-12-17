/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyPattern         = "%s_%s"
	invKeyPrefix       = "inv"
	connIDKeyPrefix    = "conn"
	connStateKeyPrefix = "connstate"
	myNSPrefix         = "my"
	// TODO: https://github.com/hyperledger/aries-framework-go/issues/556 It will not be constant, this namespace
	//  will need to be figured with verification key
	theirNSPrefix = "their"
	// limitPattern with `~` at the end for lte of given prefix (less than or equal)
	limitPattern = "%s~"
)

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

func (r *ConnectionRecord) isValid() error {
	if r.ThreadID == "" || r.ConnectionID == "" || r.Namespace == "" {
		return fmt.Errorf("input parameters thid : %s and connectionId : %s namespace : %s cannot be empty",
			r.ThreadID, r.ConnectionID, r.Namespace)
	}

	return nil
}

// NewConnectionRecorder returns new connection record instance
func NewConnectionRecorder(transientStore, store storage.Store, didMap didconnection.Store) *ConnectionRecorder {
	return &ConnectionRecorder{transientStore: transientStore, store: store, didMap: didMap}
}

// ConnectionRecorder takes care of connection related persistence features
type ConnectionRecorder struct {
	transientStore storage.Store
	store          storage.Store
	didMap         didconnection.Store
}

// SaveInvitation saves connection invitation to underlying store
//
// Args:
//
// invitation: invitation to be stored
//
// Returns:
//
// error: error
func (c *ConnectionRecorder) SaveInvitation(invitation *Invitation) error {
	k, err := invitationKey(invitation.ID)
	if err != nil {
		return err
	}

	bytes, err := json.Marshal(invitation)
	if err != nil {
		return err
	}

	return c.store.Put(k, bytes)
}

// GetInvitation returns invitation for given key from underlying store and
// stores the result in the value pointed to by v
//
// Args:
//
// id: invitation id
//
// Returns:
//
// invitation found
// error: error
func (c *ConnectionRecorder) GetInvitation(id string) (*Invitation, error) {
	k, err := invitationKey(id)
	if err != nil {
		return nil, err
	}

	bytes, err := c.store.Get(k)
	if err != nil {
		return nil, err
	}

	result := &Invitation{}

	err = json.Unmarshal(bytes, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetConnectionRecord return connection record based on the connection ID
func (c *ConnectionRecorder) GetConnectionRecord(connectionID string) (*ConnectionRecord, error) {
	rec, err := getAndUnmarshal(connectionKeyPrefix(connectionID), c.store)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return getAndUnmarshal(connectionKeyPrefix(connectionID), c.transientStore)
		}

		return nil, err
	}

	return rec, nil
}

// QueryConnectionRecords returns connection records found in underlying store
// for given query criteria
func (c *ConnectionRecorder) QueryConnectionRecords() ([]*ConnectionRecord, error) {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/655 query criteria to be added as part of issue
	searchKey := connectionKeyPrefix("")

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
		if _, ok := keys[string(transientItr.Key())]; !ok {
			var record ConnectionRecord

			err := json.Unmarshal(transientItr.Value(), &record)
			if err != nil {
				return nil, fmt.Errorf("query connection records from transient store : %w", err)
			}

			records = append(records, &record)
		}
	}

	return records, nil
}

// GetConnectionRecordAtState return connection record based on the connection ID and state.
func (c *ConnectionRecorder) GetConnectionRecordAtState(connectionID, stateID string) (*ConnectionRecord, error) {
	if stateID == "" {
		return nil, errors.New("stateID can't be empty")
	}

	return getAndUnmarshal(connectionStateKeyPrefix(connectionID, stateID), c.transientStore)
}

func getAndUnmarshal(k string, store storage.Store) (*ConnectionRecord, error) {
	connRecordBytes, err := store.Get(k)
	if err != nil {
		return nil, err
	}

	return prepareConnectionRecord(connRecordBytes)
}

// GetConnectionRecordByNSThreadID return connection record via namespaced threadID
func (c *ConnectionRecorder) GetConnectionRecordByNSThreadID(nsThreadID string) (*ConnectionRecord, error) {
	connectionIDBytes, err := c.transientStore.Get(nsThreadID)
	if err != nil {
		return nil, fmt.Errorf("get connectionID by namespaced threadID: %w", err)
	}
	// adding prefix for storing connection record
	k := connectionKeyPrefix(string(connectionIDBytes))

	connRecordBytes, err := c.transientStore.Get(k)
	if err != nil {
		return nil, fmt.Errorf("get connection record by connectionID: %w", err)
	}

	return prepareConnectionRecord(connRecordBytes)
}

// saveConnectionRecord saves the connection record against the connection id  in the store
func (c *ConnectionRecorder) saveConnectionRecord(record *ConnectionRecord) error {
	if err := marshalAndSave(connectionKeyPrefix(record.ConnectionID), record, c.transientStore); err != nil {
		return fmt.Errorf("save connection record in transient store: %w", err)
	}

	if record.State != "" {
		err := marshalAndSave(connectionStateKeyPrefix(record.ConnectionID, record.State), record, c.transientStore)
		if err != nil {
			return fmt.Errorf("save connection record with state in transient store: %w", err)
		}
	}

	if record.State == stateNameCompleted {
		if err := marshalAndSave(connectionKeyPrefix(record.ConnectionID), record, c.store); err != nil {
			return fmt.Errorf("save connection record in permanent store: %w", err)
		}

		if err := c.didMap.SaveDIDConnection(record.MyDID, record.TheirDID, record.RecipientKeys); err != nil {
			return err
		}
	}

	return nil
}

func marshalAndSave(k string, v *ConnectionRecord, store storage.Store) error {
	bytes, err := json.Marshal(v)

	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}

	return store.Put(k, bytes)
}

// saveNewConnectionRecord saves newly created connection record against the connection id in the store
// and it creates mapping from namespaced ThreadID to connection ID
func (c *ConnectionRecorder) saveNewConnectionRecord(record *ConnectionRecord) error {
	err := record.isValid()
	if err != nil {
		return err
	}

	err = c.saveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("save new connection record: %w", err)
	}

	if record.MyDID != "" {
		if err := c.didMap.SaveDIDByResolving(record.MyDID, didCommServiceType, ed25519KeyType); err != nil {
			return err
		}
	}

	return c.saveNSThreadID(record.ThreadID, record.Namespace, record.ConnectionID)
}

func (c *ConnectionRecorder) saveNSThreadID(thid, namespace, connectionID string) error {
	if namespace != myNSPrefix && namespace != theirNSPrefix {
		return fmt.Errorf("namespace not supported")
	}

	prefix := myNSPrefix
	if namespace == theirNSPrefix {
		prefix = theirNSPrefix
	}

	k, err := createNSKey(prefix, thid)
	if err != nil {
		return err
	}

	return c.transientStore.Put(k, []byte(connectionID))
}

func prepareConnectionRecord(connRecBytes []byte) (*ConnectionRecord, error) {
	connRecord := &ConnectionRecord{}

	err := json.Unmarshal(connRecBytes, connRecord)
	if err != nil {
		return nil, fmt.Errorf("prepare connection record: %w", err)
	}

	return connRecord, nil
}

// invitationKey computes key for invitation object
func invitationKey(invID string) (string, error) {
	storeKey, err := computeHash([]byte(invID))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(keyPattern, invKeyPrefix, storeKey), nil
}

// computeHash will compute the hash for the supplied bytes
func computeHash(bytes []byte) (string, error) {
	if len(bytes) == 0 {
		return "", errors.New("unable to compute hash, empty bytes")
	}

	h := crypto.SHA256.New()
	hash := h.Sum(bytes)

	return fmt.Sprintf("%x", hash), nil
}

// connectionKeyPrefix computes key for connection record object
func connectionKeyPrefix(connectionID string) string {
	return fmt.Sprintf(keyPattern, connIDKeyPrefix, connectionID)
}

// connectionStateKeyPrefix computes key for connection record data associated with state.
func connectionStateKeyPrefix(connectionID, stateID string) string {
	return fmt.Sprintf(keyPattern, connStateKeyPrefix, connectionID+stateID)
}

// createNSKey computes key for storing the mapping with the namespace
func createNSKey(prefix, id string) (string, error) {
	storeKey, err := computeHash([]byte(id))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(keyPattern, prefix, storeKey), nil
}
