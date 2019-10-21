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

	"github.com/hyperledger/aries-framework-go/pkg/didmethod/peer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyStoreNamespace = "keystore"
	didStoreNamespace = "didstore"
	peerDIDMethod     = "peer"
)

// provider contains dependencies for the base wallet and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
	InboundTransportEndpoint() string
}

// BaseWallet wallet implementation
type BaseWallet struct {
	keystore                 storage.Store
	didstore                 storage.Store
	inboundTransportEndpoint string
}

// New return new instance of wallet implementation
func New(ctx provider) (*BaseWallet, error) {
	ks, err := ctx.StorageProvider().OpenStore(keyStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", keyStoreNamespace, err)
	}

	ds, err := ctx.StorageProvider().OpenStore(didStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", didStoreNamespace, err)
	}

	return &BaseWallet{keystore: ks, didstore: ds, inboundTransportEndpoint: ctx.InboundTransportEndpoint()}, nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (w *BaseWallet) CreateEncryptionKey() (string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if err := persist(w.keystore, base58Pub, &cryptoutil.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
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
	if err := persist(w.keystore, base58Pub, &cryptoutil.KeyPair{Pub: pub[:], Priv: priv[:]}); err != nil {
		return "", err
	}
	return base58Pub, nil
}

// ConvertToEncryptionKey converts an ed25519 keypair present in the wallet,
// persists the resulting keypair, and returns the result public key.
func (w *BaseWallet) ConvertToEncryptionKey(key []byte) ([]byte, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(key)
	if err != nil {
		return nil, err
	}
	encPubB58 := base58.Encode(encPub)

	keyB58 := base58.Encode(key)
	kp, err := w.getKey(keyB58)
	if err != nil {
		return nil, err
	}
	encPriv, err := cryptoutil.SecretEd25519toCurve25519(kp.Priv)
	if err != nil {
		return nil, err
	}
	kpEnc := cryptoutil.KeyPair{Priv: encPriv, Pub: encPub}
	err = persist(w.keystore, encPubB58, &kpEnc)
	if err != nil {
		return nil, err
	}

	return encPub, nil
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
func (w *BaseWallet) CreateDID(method string, opts ...DocOpts) (*did.Doc, error) {
	docOpts := &createDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	// Generate key pair
	base58PubKey, err := w.CreateEncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	var didDoc *did.Doc

	switch method {
	case peerDIDMethod:
		didDoc, err = w.buildPeerDIDDoc(base58PubKey, docOpts)
		if err != nil {
			return nil, fmt.Errorf("create peer DID : %w", err)
		}
	default:
		return nil, errors.New("invalid DID Method")
	}

	// persist in did store
	err = persist(w.didstore, didDoc.ID, didDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to persist DID : %w", err)
	}

	return didDoc, nil
}

// GetDID gets already created DID document from underlying store
func (w *BaseWallet) GetDID(id string) (*did.Doc, error) {
	bytes, err := w.didstore.Get(id)
	if err != nil {
		return nil, err
	}

	didDoc := did.Doc{}
	if err := json.Unmarshal(bytes, &didDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal did document: %w", err)
	}

	return &didDoc, nil
}

// getKey get key
func (w *BaseWallet) getKey(verkey string) (*cryptoutil.KeyPair, error) {
	bytes, err := w.keystore.Get(verkey)
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

// persist marshals value and saves it in store for given key
func persist(store storage.Store, key string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal : %w", err)
	}
	err = store.Put(key, bytes)
	if err != nil {
		return fmt.Errorf("failed to save in store: %w", err)
	}
	return nil
}

func (w *BaseWallet) buildPeerDIDDoc(base58PubKey string, docOpts *createDIDOpts) (*did.Doc, error) {
	// Supporting only one public key now
	publicKey := did.PublicKey{
		ID: base58PubKey[0:7],
		// TODO hardcoding public key type for now
		// Should be dynamic for multi-key support
		Type:       "Ed25519VerificationKey2018",
		Controller: "#id",
		Value:      []byte(base58PubKey),
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service
	if docOpts.serviceType != "" {
		// Service endpoints
		service = []did.Service{
			{
				ID:              "#agent",
				Type:            docOpts.serviceType,
				ServiceEndpoint: w.inboundTransportEndpoint,
			},
		}
	}

	// Created/Updated time
	t := time.Now()

	return peer.NewDoc(
		[]did.PublicKey{publicKey},
		[]did.VerificationMethod{
			{PublicKey: publicKey},
		},
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
	)
}
