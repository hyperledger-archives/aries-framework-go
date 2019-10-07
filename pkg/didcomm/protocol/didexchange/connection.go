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

// NewConnectionRecorder returns new connection record instance
func NewConnectionRecorder(store storage.Store) *ConnectionRecorder {
	return &ConnectionRecorder{store: store}
}

// ConnectionRecorder takes care of connection related persistence features
type ConnectionRecorder struct {
	store            storage.Store
    connectionRecord  connectionRecord
}

type connectionRecord struct {
	ThreadID        string
	ID              string
	MyDID           string
	TheirDID        string
	TheirLabel      string
	State           string
	ServiceEndPoint string
	RecKey          []string
	InvitationID    string
}

// SaveInvitation saves connection invitation to underlying store
//
// Args:
//
// key: key for the invitation object to be saved in store
// value: invitation object
//
// Returns:
//
// error: error
func (c *ConnectionRecorder) SaveInvitation(key string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	storeKey, err := computeHash([]byte(key))
	if err != nil {
		return err
	}

	return c.store.Put(storeKey, bytes)
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

func (c *ConnectionRecorder) SaveConnectionRecorder(msg *Message) error {
	invitation := &Invitation{}
	err := json.Unmarshal(msg.Msg.Payload, invitation)
	if err != nil {
		return fmt.Errorf("error while unmarshalling save connection record %s : ", err)
	}
	connRecord := &connectionRecord{ThreadID: msg.ThreadID,ServiceEndPoint:invitation.ServiceEndpoint, RecKey:invitation.RecipientKeys,State:msg.State}
	connBytes, err := json.Marshal(connRecord)
	if err != nil {
		return fmt.Errorf("error while marshalling save connection record %s : ", err)
	}
	err = c.store.Put(msg.ConnectionID, connBytes)
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}
func (c *ConnectionRecorder) SaveProtocolID(newDid string, msg *Message) error {
	if len(newDid) == 0 {
		request := &Request{}
		err := json.Unmarshal(msg.Msg.Payload, request)
		if err != nil {
			return err
		}
		newDid = request.Connection.DID
	}
	protocolID, err := computeHash([]byte(msg.ThreadID + newDid))
	if err != nil {
		return err
	}
	err = c.store.Put(protocolID, []byte(msg.ConnectionID))
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func (c *ConnectionRecorder) FindByProtocolID(myDID, thid string)(string, error) {
	protocolID,err := computeHash([]byte(thid + myDID))
	if err != nil {
		return "", err
	}
	connectionIDBytes, err := c.store.Get(protocolID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return "", nil
		}
		return "",  fmt.Errorf("cannot fetch state from store: err=%s",err)
	}
	return string(connectionIDBytes), nil
}

func (c *ConnectionRecorder) FindByConnectionID(connectionID string)(string, error) {
	connBytes, err := c.store.Get(connectionID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("cannot fetch state from store: connectionID=%s err=%s", connectionID, err)
	}
	connRecord := &c.connectionRecord
	err = json.Unmarshal(connBytes, &c.connectionRecord)
	if err!= nil {
		return "", err
	}
	return connRecord.State, nil
}
