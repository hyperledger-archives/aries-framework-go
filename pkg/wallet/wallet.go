/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// BaseWallet wallet implementation
type BaseWallet struct {
	store   storage.Store
	crypter crypto.Crypter
}

// TODO use the context / provider mechanism
// New return new instance of wallet implementation
func New(storeProvider storage.Provider, crypter crypto.Crypter) (*BaseWallet, error) {
	store, err := storeProvider.GetStoreHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to GetStoreHandle: %w", err)
	}
	return &BaseWallet{store: store, crypter: crypter}, nil
}

// CreateKey create a new public/private signing keypair.
func (w *BaseWallet) CreateKey() (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(base58Pub, &crypto.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
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
	if envelope == nil {
		return nil, errors.New("envelope argument is nil")
	}
	// get keypair from db
	senderKeyPair, err := w.getKey(envelope.FromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed from getKey: %w", err)
	}

	var recipients [][]byte
	for _, verKey := range envelope.ToVerKeys {
		// TODO It is possible to have different key schemes in an interop situation
		// there is no guarantee that each recipient is using the same key types
		// decode base58 ver key
		verKeyBytes := base58.Decode(verKey)
		// create 32 byte key
		recipients = append(recipients, verKeyBytes)
	}
	// encrypt message
	bytes, err := w.crypter.Encrypt(envelope.Message, *senderKeyPair, recipients)
	if err != nil {
		return nil, fmt.Errorf("failed from encrypt: %w", err)
	}
	return bytes, nil
}

// UnpackMessage Unpack a message.
func (w *BaseWallet) UnpackMessage(encMessage []byte) (*Envelope, error) {
	var e authcrypt.Envelope
	if err := json.Unmarshal(encMessage, &e); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encMessage: %w", err)
	}
	var keysNotFound []string
	for _, v := range e.Recipients {
		recipVKeyB58 := v.Header.KID
		// get keypair from db
		recipientKeyPair, err := w.getKey(recipVKeyB58)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) {
				keysNotFound = append(keysNotFound, recipVKeyB58)
				continue
			}
			return nil, fmt.Errorf("failed from getKey: %w", err)
		}
		bytes, err := w.crypter.Decrypt(encMessage, *recipientKeyPair)
		if err != nil {
			return nil, fmt.Errorf("failed from decrypt: %w", err)
		}
		return &Envelope{Message: bytes}, nil
	}
	return nil, fmt.Errorf("no corresponding recipient key found in {%s}", keysNotFound)
}

// Close wallet
func (w *BaseWallet) Close() error {
	return nil
}

// persistKey save key in storage
func (w *BaseWallet) persistKey(key string, value *crypto.KeyPair) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	err = w.store.Put(key, bytes)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	return nil
}

// getKey get key
func (w *BaseWallet) getKey(verkey string) (*crypto.KeyPair, error) {
	bytes, err := w.store.Get(verkey)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	var key crypto.KeyPair
	if err := json.Unmarshal(bytes, &key); err != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", err)
	}
	return &key, nil
}
