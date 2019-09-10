/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// BaseWallet wallet implementation
type BaseWallet struct {
	store storage.Store
}

// key json structure include public,private and metadata
type key struct {
	Public  string    `json:"public"`
	Private *[32]byte `json:"private"`
}

// New return new instance of wallet implementation
func New(storeProvider storage.Provider) (*BaseWallet, error) {
	store, err := storeProvider.GetStoreHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to GetStoreHandle: %w", err)
	}
	return &BaseWallet{store: store}, nil
}

// CreateKey create a new public/private signing keypair.
func (w *BaseWallet) CreateKey() (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(&key{Public: base58Pub, Private: priv}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// SignMessage sign a message using the private key associated with a given verification key.
func (w *BaseWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// DecryptMessage decrypt message
func (w *BaseWallet) DecryptMessage(encMessage []byte, toVerKey string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("not implemented")
}

// PackMessage Pack a message for one or more recipients.
func (w *BaseWallet) PackMessage(envelope *Envelope) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// UnpackMessage Unpack a message.
func (w *BaseWallet) UnpackMessage(encMessage []byte) (*Envelope, error) {
	return nil, fmt.Errorf("not implemented")
}

// Close wallet
func (w *BaseWallet) Close() error {
	return nil
}

// persistKey save key in storage
func (w *BaseWallet) persistKey(key *key) error {
	bytes, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	err = w.store.Put(key.Public, bytes)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	return nil
}
