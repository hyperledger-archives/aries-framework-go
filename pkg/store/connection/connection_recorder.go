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
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// StateNameCompleted completed state.
	StateNameCompleted = "completed"
	// MyNSPrefix namespace val my.
	MyNSPrefix = "my"
	// TheirNSPrefix namespace val their
	// TODO: https://github.com/hyperledger/aries-framework-go/issues/556 It will not be constant, this namespace
	//  will need to be figured with verification key
	TheirNSPrefix    = "their"
	errMsgInvalidKey = "invalid key"
)

// NewRecorder returns new connection recorder.
// Recorder is read-write connection store which provides
// write features on top query features from Lookup.
func NewRecorder(p provider) (*Recorder, error) {
	lookup, err := NewLookup(p)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection recorder : %w", err)
	}

	return &Recorder{lookup}, nil
}

// Recorder is read-write connection store.
type Recorder struct {
	*Lookup
}

// SaveInvitation saves invitation in permanent store for given key.
// TODO should avoid using target of type `interface{}` [Issue #1030].
func (c *Recorder) SaveInvitation(id string, invitation interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return marshalAndSave(getInvitationKeyPrefix()(id), invitation, c.store)
}

// SaveOOBv2Invitation saves OOBv2 invitation in permanent store under given ID.
// TODO should avoid using target of type `interface{}` [Issue #1030].
func (c *Recorder) SaveOOBv2Invitation(myDID string, invitation interface{}) error {
	if myDID == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return marshalAndSave(getOOBInvitationV2KeyPrefix()(tagValueFromDIDs(myDID)), invitation, c.store)
}

// SaveConnectionRecord saves given connection records in underlying store.
func (c *Recorder) SaveConnectionRecord(record *Record) error {
	if err := marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID),
		record, c.protocolStateStore, storage.Tag{
			Name:  getConnectionKeyPrefix()(""),
			Value: getConnectionKeyPrefix()(record.ConnectionID),
		}); err != nil {
		return fmt.Errorf("save connection record in protocol state store: %w", err)
	}

	if record.State != "" {
		err := marshalAndSave(getConnectionStateKeyPrefix()(record.ConnectionID, record.State),
			record, c.protocolStateStore, storage.Tag{
				Name:  connStateKeyPrefix,
				Value: getConnectionStateKeyPrefix()(record.ConnectionID),
			})
		if err != nil {
			return fmt.Errorf("save connection record with state in protocol state store: %w", err)
		}
	}

	if record.State == StateNameCompleted {
		if err := marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID),
			record, c.store, storage.Tag{
				Name:  getConnectionKeyPrefix()(""),
				Value: getConnectionKeyPrefix()(record.ConnectionID),
			},
			storage.Tag{
				Name:  bothDIDsTagName,
				Value: tagValueFromDIDs(record.MyDID, record.TheirDID),
			},
			storage.Tag{
				Name:  theirDIDTagName,
				Value: tagValueFromDIDs(record.TheirDID),
			}); err != nil {
			return fmt.Errorf("save connection record in permanent store: %w", err)
		}
	}

	return nil
}

// SaveConnectionRecordWithMappings saves newly created connection record against the connection id in the store
// and it creates mapping from namespaced ThreadID to connection ID.
func (c *Recorder) SaveConnectionRecordWithMappings(record *Record) error {
	err := isValidConnection(record)
	if err != nil {
		return fmt.Errorf("validation failed while saving connection record with mapping: %w", err)
	}

	err = c.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("failed to save connection record with mappings: %w", err)
	}

	err = c.SaveNamespaceThreadID(record.ThreadID, record.Namespace, record.ConnectionID)
	if err != nil {
		return fmt.Errorf("failed to save connection record with namespace mappings: %w", err)
	}

	return nil
}

// SaveEvent saves event related data for given connection ID
// TODO connection event data shouldn't be transient [Issues #1029].
func (c *Recorder) SaveEvent(connectionID string, data []byte) error {
	return c.protocolStateStore.Put(getEventDataKeyPrefix()(connectionID), data)
}

// SaveNamespaceThreadID saves given namespace, threadID and connection ID mapping in protocol state store.
func (c *Recorder) SaveNamespaceThreadID(threadID, namespace, connectionID string) error {
	if namespace != MyNSPrefix && namespace != TheirNSPrefix {
		return fmt.Errorf("namespace not supported")
	}

	prefix := MyNSPrefix
	if namespace == TheirNSPrefix {
		prefix = TheirNSPrefix
	}

	key, err := computeHash([]byte(threadID))
	if err != nil {
		return err
	}

	return c.protocolStateStore.Put(getNamespaceKeyPrefix(prefix)(key), []byte(connectionID))
}

// RemoveConnection removes connection record from the store for given id.
func (c *Recorder) RemoveConnection(connectionID string) error {
	record, err := c.GetConnectionRecord(connectionID)
	if err != nil {
		return fmt.Errorf("unable to get connection record: connectionid=%s err=%w", connectionID, err)
	}

	if err = c.protocolStateStore.Delete(getConnectionKeyPrefix()(connectionID)); err != nil {
		return fmt.Errorf("unable to delete connection record from the protocol state store: connectionid=%s err=%w",
			connectionID, err)
	}

	// remove connection records for different states from protocol state store
	err = removeConnectionsForStates(c, connectionID)
	if err != nil {
		return fmt.Errorf("remove records for different connections states error: %w", err)
	}

	err = c.store.Delete(getConnectionKeyPrefix()(connectionID))
	if err != nil {
		return fmt.Errorf("unable to delete connection record from the store: connectionid=%s err=%w", connectionID, err)
	}

	// remove namespace, threadID and connection ID mapping from protocol state store
	err = removeMappings(c, record)
	if err != nil {
		return fmt.Errorf("unable to delete connection record with namespace mappings: %w", err)
	}

	return nil
}

func marshalAndSave(k string, v interface{}, store storage.Store, tags ...storage.Tag) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}

	return store.Put(k, bytes, tags...)
}

// isValidConnection validates connection record.
func isValidConnection(r *Record) error {
	if r.ThreadID == "" || r.ConnectionID == "" || r.Namespace == "" {
		return fmt.Errorf("input parameters thid : %s and connectionId : %s namespace : %s cannot be empty",
			r.ThreadID, r.ConnectionID, r.Namespace)
	}

	return nil
}

// computeHash will compute the hash for the supplied bytes.
func computeHash(bytes []byte) (string, error) {
	if len(bytes) == 0 {
		return "", errors.New("unable to compute hash, empty bytes")
	}

	h := crypto.SHA256.New()
	hash := h.Sum(bytes)

	return fmt.Sprintf("%x", hash), nil
}

func removeConnectionsForStates(c *Recorder, connectionID string) error {
	itr, err := c.protocolStateStore.Query(fmt.Sprintf("%s:%s", connStateKeyPrefix,
		getConnectionStateKeyPrefix()(connectionID)))
	if err != nil {
		return fmt.Errorf("failed to query protocol state store: %w", err)
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close iterator: %s", errClose.Error())
		}
	}()

	more, err := itr.Next()
	if err != nil {
		return fmt.Errorf("failed to get next set of data from iterator: %w", err)
	}

	for more {
		key, err := itr.Key()
		if err != nil {
			return fmt.Errorf("failed to get key from iterator: %w", err)
		}

		err = c.protocolStateStore.Delete(key)
		if err != nil {
			return fmt.Errorf(
				"unable to delete connection state record from the protocol state store: key=%s connectionid=%s err=%w",
				key, connectionID, err)
		}

		more, err = itr.Next()
		if err != nil {
			return fmt.Errorf("failed to get next set of data from iterator: %w", err)
		}
	}

	return nil
}

func removeMappings(c *Recorder, record *Record) error {
	key, err := computeHash([]byte(record.ThreadID))
	if err != nil {
		return fmt.Errorf("compute hash: %w", err)
	}

	return c.store.Delete(getNamespaceKeyPrefix(record.Namespace)(key))
}
