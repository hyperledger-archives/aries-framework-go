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

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	stateNameCompleted = "completed"
	myNSPrefix         = "my"
	// TODO: https://github.com/hyperledger/aries-framework-go/issues/556 It will not be constant, this namespace
	//  will need to be figured with verification key
	theirNSPrefix    = "their"
	errMsgInvalidKey = "invalid key"
)

// NewRecorder returns new connection recorder.
// Recorder is read-write connection store which provides
// write features on top query features from Lookup
func NewRecorder(p provider) (*Recorder, error) {
	lookup, err := NewLookup(p)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection recorder : %w", err)
	}

	return &Recorder{lookup}, nil
}

// Recorder is read-write connection store
type Recorder struct {
	*Lookup
}

// SaveInvitation saves invitation in permanent store for given key
// TODO should avoid using target of type `interface{}` [Issue #1030]
func (c *Recorder) SaveInvitation(id string, invitation interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return marshalAndSave(getInvitationKeyPrefix()(id), invitation, c.store)
}

// SaveConnectionRecord saves given connection records in underlying store
func (c *Recorder) SaveConnectionRecord(record *Record) error {
	if err := marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID),
		record, c.transientStore); err != nil {
		return fmt.Errorf("save connection record in transient store: %w", err)
	}

	if record.State != "" {
		err := marshalAndSave(getConnectionStateKeyPrefix()(record.ConnectionID, record.State),
			record, c.transientStore)
		if err != nil {
			return fmt.Errorf("save connection record with state in transient store: %w", err)
		}
	}

	if record.State == stateNameCompleted {
		if err := marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID),
			record, c.store); err != nil {
			return fmt.Errorf("save connection record in permanent store: %w", err)
		}

		// create map between DIDs and ConnectionID
		if err := c.store.Put(getDIDConnMapKeyPrefix()(record.MyDID, record.TheirDID),
			[]byte(record.ConnectionID)); err != nil {
			return fmt.Errorf("save did and connection map in store: %w", err)
		}
	}

	return nil
}

// SaveConnectionRecordWithMappings saves newly created connection record against the connection id in the store
// and it creates mapping from namespaced ThreadID to connection ID
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
// TODO connection event data shouldn't be transient [Issues #1029]
func (c *Recorder) SaveEvent(connectionID string, data []byte) error {
	return c.transientStore.Put(getEventDataKeyPrefix()(connectionID), data)
}

// SaveNamespaceThreadID saves given namespace, threadID and connection ID mapping in transient store
func (c *Recorder) SaveNamespaceThreadID(threadID, namespace, connectionID string) error {
	if namespace != myNSPrefix && namespace != theirNSPrefix {
		return fmt.Errorf("namespace not supported")
	}

	prefix := myNSPrefix
	if namespace == theirNSPrefix {
		prefix = theirNSPrefix
	}

	key, err := computeHash([]byte(threadID))
	if err != nil {
		return err
	}

	return c.transientStore.Put(getNamespaceKeyPrefix(prefix)(key), []byte(connectionID))
}

func marshalAndSave(k string, v interface{}, store storage.Store) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}

	return store.Put(k, bytes)
}

// isValidConnection validates connection record
func isValidConnection(r *Record) error {
	if r.ThreadID == "" || r.ConnectionID == "" || r.Namespace == "" {
		return fmt.Errorf("input parameters thid : %s and connectionId : %s namespace : %s cannot be empty",
			r.ThreadID, r.ConnectionID, r.Namespace)
	}

	return nil
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
