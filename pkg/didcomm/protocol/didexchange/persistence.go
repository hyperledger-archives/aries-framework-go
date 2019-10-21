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

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyPattern      = "%s_%s"
	invKeyPrefix    = "inv"
	connIDKeyPrefix = "conn"
	myNSPrefix      = "my"
	//Todo: Issue-556 It will not be constant, this namespace will need to be figured with verification key
	theirNSPrefix = "their"
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
func NewConnectionRecorder(store storage.Store) *ConnectionRecorder {
	return &ConnectionRecorder{store: store}
}

// ConnectionRecorder takes care of connection related persistence features
type ConnectionRecorder struct {
	store storage.Store
}

// SaveInvitation saves connection invitation to underlying store
//
// Args:
//
// verKey: recipient key of the invitation object to be saved in store
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
	k := connectionKeyPrefix(connectionID)
	connRecordBytes, err := c.store.Get(k)
	if err != nil {
		return nil, fmt.Errorf("get connection record: %w", err)
	}
	return prepareConnectionRecord(connRecordBytes)
}

// GetConnectionRecordByNSThreadID return connection record via namespaced threadID
func (c *ConnectionRecorder) GetConnectionRecordByNSThreadID(nsThreadID string) (*ConnectionRecord, error) {
	connectionIDBytes, err := c.store.Get(nsThreadID)
	if err != nil {
		return nil, fmt.Errorf("get connectionID by namespaced threadID: %w", err)
	}
	// adding prefix for storing connection record
	k := connectionKeyPrefix(string(connectionIDBytes))

	connRecordBytes, err := c.store.Get(k)
	if err != nil {
		return nil, fmt.Errorf("get connection record by connectionID: %w", err)
	}
	return prepareConnectionRecord(connRecordBytes)
}

// saveConnectionRecord saves the connection record against the connection id  in the store
func (c *ConnectionRecorder) saveConnectionRecord(record *ConnectionRecord) error {
	k := connectionKeyPrefix(record.ConnectionID)
	bytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}
	return c.store.Put(k, bytes)
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

	return c.store.Put(k, []byte(connectionID))
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
func invitationKey(verKey string) (string, error) {
	storeKey, err := computeHash([]byte(verKey))
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

// createNSKey computes key for storing the mapping with the namespace
func createNSKey(prefix, id string) (string, error) {
	storeKey, err := computeHash([]byte(id))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(keyPattern, prefix, storeKey), nil
}
