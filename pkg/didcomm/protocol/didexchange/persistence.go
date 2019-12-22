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

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyPattern   = "%s_%s"
	invKeyPrefix = "inv"
	myNSPrefix   = "my"
	// TODO: https://github.com/hyperledger/aries-framework-go/issues/556 It will not be constant, this namespace
	//  will need to be figured with verification key
	theirNSPrefix = "their"
)

// newConnectionStore returns new connection store instance
func newConnectionStore(p provider) (*connectionStore, error) {
	reader, err := connectionstore.NewConnectionLookup(p)
	if err != nil {
		return nil, err
	}

	return &connectionStore{ConnectionLookup: reader, didStore: p.DIDConnectionStore()}, nil
}

// connectionStore takes care of connection and DID related persistence features
// TODO this should be moved to separate package as Writable connection store [Issue #1021]
// TODO merge connection stores [Issue #1004]
type connectionStore struct {
	*connectionstore.ConnectionLookup
	didStore didconnection.Store
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
func (c *connectionStore) SaveInvitation(invitation *Invitation) error {
	k, err := invitationKey(invitation.ID)
	if err != nil {
		return err
	}

	bytes, err := json.Marshal(invitation)
	if err != nil {
		return err
	}

	return c.Store().Put(k, bytes)
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
func (c *connectionStore) GetInvitation(id string) (*Invitation, error) {
	k, err := invitationKey(id)
	if err != nil {
		return nil, err
	}

	bytes, err := c.Store().Get(k)
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

// saveConnectionRecord saves the connection record against the connection id  in the store
func (c *connectionStore) saveConnectionRecord(record *connectionstore.ConnectionRecord) error {
	if err := marshalAndSave(connectionstore.GetConnectionKeyPrefix()(record.ConnectionID),
		record, c.TransientStore()); err != nil {
		return fmt.Errorf("save connection record in transient store: %w", err)
	}

	if record.State != "" {
		err := marshalAndSave(connectionstore.GetConnectionStateKeyPrefix()(record.ConnectionID, record.State),
			record, c.TransientStore())
		if err != nil {
			return fmt.Errorf("save connection record with state in transient store: %w", err)
		}
	}

	if record.State == stateNameCompleted {
		if err := marshalAndSave(connectionstore.GetConnectionKeyPrefix()(record.ConnectionID),
			record, c.Store()); err != nil {
			return fmt.Errorf("save connection record in permanent store: %w", err)
		}

		if err := c.didStore.SaveDIDByResolving(record.TheirDID, record.RecipientKeys...); err != nil {
			return err
		}
	}

	return nil
}

func marshalAndSave(k string, v *connectionstore.ConnectionRecord, store storage.Store) error {
	bytes, err := json.Marshal(v)

	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}

	return store.Put(k, bytes)
}

// saveNewConnectionRecord saves newly created connection record against the connection id in the store
// and it creates mapping from namespaced ThreadID to connection ID
func (c *connectionStore) saveNewConnectionRecord(record *connectionstore.ConnectionRecord) error {
	err := isValidConnection(record)
	if err != nil {
		return err
	}

	err = c.saveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("save new connection record: %w", err)
	}

	if record.MyDID != "" {
		if err := c.didStore.SaveDIDByResolving(record.MyDID); err != nil {
			return err
		}
	}

	return c.saveNSThreadID(record.ThreadID, record.Namespace, record.ConnectionID)
}

func (c *connectionStore) saveNSThreadID(thid, namespace, connectionID string) error {
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

	return c.TransientStore().Put(k, []byte(connectionID))
}

// invitationKey computes key for invitation object
func invitationKey(invID string) (string, error) {
	storeKey, err := computeHash([]byte(invID))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(keyPattern, invKeyPrefix, storeKey), nil
}

// createNSKey computes key for storing the mapping with the namespace
func createNSKey(prefix, id string) (string, error) {
	storeKey, err := computeHash([]byte(id))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(keyPattern, prefix, storeKey), nil
}

func isValidConnection(r *connectionstore.ConnectionRecord) error {
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
