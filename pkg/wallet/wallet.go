/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	storageName  = "basewallet"
	didFormat    = "did:%s:%s"
	didPKID      = "%s#keys-%d"
	didServiceID = "%s#endpoint-%d"
)

// provider contains dependencies for the base wallet and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
	InboundTransportEndpoint() string
}

// BaseWallet wallet implementation
type BaseWallet struct {
	store                    storage.Store
	inboundTransportEndpoint string
}

// New return new instance of wallet implementation
func New(ctx provider) (*BaseWallet, error) {
	store, err := ctx.StorageProvider().OpenStore(storageName)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", storageName, err)
	}

	return &BaseWallet{store: store, inboundTransportEndpoint: ctx.InboundTransportEndpoint()}, nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (w *BaseWallet) CreateEncryptionKey() (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(base58Pub, &cryptoutil.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// CreateSigningKey create a new public/private signing keypair.
func (w *BaseWallet) CreateSigningKey() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := w.persistKey(base58Pub, &cryptoutil.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// SignMessage sign a message using the private key associated with a given verification key.
func (w *BaseWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	keyPair, err := w.getKey(fromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return ed25519signature2018.New().Sign(keyPair.Priv, message)
}

// Close wallet
func (w *BaseWallet) Close() error {
	return nil
}

// CreateDID returns new DID Document
// TODO write the DID Doc to the chosen DID method.
func (w *BaseWallet) CreateDID(method string, opts ...DocOpts) (*did.Doc, error) {
	docOpts := &createDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	// Generate key pair
	pub, err := w.CreateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	// DID identifier
	id := fmt.Sprintf(didFormat, method, pub[:16])

	// Supporting only one public key now
	pubKey := did.PublicKey{
		ID: fmt.Sprintf(didPKID, id, 1),
		// TODO hardcoding public key type for now
		// Should be dynamic for multi-key support
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(pub),
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service
	if docOpts.serviceType != "" {
		// Service endpoints
		service = []did.Service{
			{
				ID:              fmt.Sprintf(didServiceID, id, 1),
				Type:            docOpts.serviceType,
				ServiceEndpoint: w.inboundTransportEndpoint,
			},
		}
	}

	// Created time
	createdTime := time.Now()

	return &did.Doc{
		Context:   []string{did.Context},
		ID:        id,
		PublicKey: []did.PublicKey{pubKey},
		Service:   service,
		Created:   &createdTime,
		Updated:   &createdTime,
	}, nil
}

// persistKey save key in storage
func (w *BaseWallet) persistKey(key string, value *cryptoutil.KeyPair) error {
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
func (w *BaseWallet) getKey(verkey string) (*cryptoutil.KeyPair, error) {
	bytes, err := w.store.Get(verkey)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, cryptoutil.ErrKeyNotFound
		}
		return nil, err
	}
	var key cryptoutil.KeyPair
	if err := json.Unmarshal(bytes, &key); err != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", err)
	}
	return &key, nil
}

// DeriveKEK will derive an ephemeral symmetric key (kek) using a private key fetched from
// the wallet corresponding to fromPubKey and derived with toPubKey
// This implementation is for curve 25519 only
func (w *BaseWallet) DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	if fromPubKey == nil || toPubKey == nil {
		return nil, cryptoutil.ErrInvalidKey
	}
	fromPrivKey := new([chacha.KeySize]byte)
	copy(fromPrivKey[:], fromPubKey)

	// get keypair from wallet store
	walletKeyPair, err := w.getKey(base58.Encode(fromPubKey))
	if err != nil {
		return nil, fmt.Errorf("failed from getKey: %w", err)
	}
	copy(fromPrivKey[:], walletKeyPair.Priv)

	toKey := new([chacha.KeySize]byte)
	copy(toKey[:], toPubKey)
	return cryptoutil.Derive25519KEK(alg, apu, fromPrivKey, toKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the wallet
func (w *BaseWallet) FindVerKey(candidateKeys []string) (int, error) {
	for i, key := range candidateKeys {
		_, err := w.getKey(key)
		if err != nil {
			if errors.Is(err, cryptoutil.ErrKeyNotFound) {
				continue
			}
			return -1, fmt.Errorf("failed from getKey: %w", err)
		}
		// Currently chooses the first usable key, but could use different logic (eg, priorities)
		return i, nil
	}
	return -1, cryptoutil.ErrKeyNotFound
}
