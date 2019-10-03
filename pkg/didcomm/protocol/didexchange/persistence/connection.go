/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package persistence

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
	store storage.Store
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
