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
	//Todo: It will not be constant, this name space will need to be figured with verification key
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

// GetConnectionRecord return connection record
func (c *ConnectionRecorder) GetConnectionRecord(thid string) (*ConnectionRecord, error) {
	connectionID, err := c.getConnectionID(thid)
	if err != nil {
		return nil, err
	}
	k := connectionKeyPrefix(connectionID)
	connRecordBytes, err := c.store.Get(k)
	if err != nil {
		return nil, err
	}
	connRecord := &ConnectionRecord{}
	err = json.Unmarshal(connRecordBytes, connRecord)
	if err != nil {
		return nil, err
	}
	return connRecord, nil
}

// saveConnectionRecord saves the connection record against the connection id  in the store
func (c *ConnectionRecorder) saveConnectionRecord(record *ConnectionRecord) error {
	if record.ConnectionID == "" || record.Namespace == "" {
		return fmt.Errorf("connectionID or namespace is empty")
	}
	k := connectionKeyPrefix(record.ConnectionID)
	bytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("error while marshalling save connection record %s : ", err)
	}
	return c.store.Put(k, bytes)
}

// saveNewConnectionRecord saves the connection record against the connection id  in the store
func (c *ConnectionRecorder) saveNewConnectionRecord(record *ConnectionRecord) error {
	if record.ThreadID == "" || record.ConnectionID == "" || record.Namespace == "" {
		return fmt.Errorf("input parameters thid -> %s and connectionId-> %s namespace-> %s cannot be empty",
			record.ThreadID, record.ConnectionID, record.Namespace)
	}
	k := connectionKeyPrefix(record.ConnectionID)
	bytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("error while marshalling save connection record %s : ", err)
	}
	err = c.saveThreadID(record.ThreadID, record.ConnectionID, record.Namespace)
	if err != nil {
		return err
	}
	return c.store.Put(k, bytes)
}
func (c *ConnectionRecorder) saveThreadID(thid, connectionID, namespace string) error {
	switch namespace {
	case myNSPrefix:
		k, err := createMyNSKey(thid)
		if err != nil {
			return err
		}
		return c.store.Put(k, []byte(connectionID))
	case theirNSPrefix:
		k, err := createTheirNSKey(thid)
		if err != nil {
			return err
		}
		return c.store.Put(k, []byte(connectionID))
	default:
		return fmt.Errorf("namespace not supported")
	}
}

// getConnectionID enables you to fetch the connection id based on the thread ID
func (c *ConnectionRecorder) getConnectionID(thid string) (string, error) {
	connectionIDBytes, err := c.store.Get(thid)
	if err != nil {
		return "", err
	}
	return string(connectionIDBytes), nil
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

// connectionKey computes key for connection record object
func connectionKeyPrefix(connectionID string) string {
	return fmt.Sprintf(keyPattern, connIDKeyPrefix, connectionID)
}

// createMyNSKey computes key for storing connection ID
func createMyNSKey(protocolID string) (string, error) {
	storeKey, err := computeHash([]byte(protocolID))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(keyPattern, myNSPrefix, storeKey), nil
}

// createTheirNSKey computes key for storing their thid
func createTheirNSKey(thid string) (string, error) {
	storeKey, err := computeHash([]byte(thid))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(keyPattern, theirNSPrefix, storeKey), nil
}
