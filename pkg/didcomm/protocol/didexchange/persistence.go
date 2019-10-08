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
	keyPattern   = "%s_%s"
	invKeyPrefix = "inv_"
)

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
func (c *ConnectionRecorder) SaveInvitation(verKey string, invitation *Invitation) error {
	k, err := invitationKey(verKey)
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
// verKey: recipient key of the invitation object to be saved in store
//
// Returns:
//
// invitation found
// error: error
func (c *ConnectionRecorder) GetInvitation(verKey string) (*Invitation, error) {
	k, err := invitationKey(verKey)
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
