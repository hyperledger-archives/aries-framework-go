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

	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/internal/didopts"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator"
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

// SecretWallet wallet implementation, including access to private keys.
// Note: this is not exposed to the rest of the library, only to pkg/crypto.
// Other packages need to use pkg/crypto/wallet, which wraps this,
//   hiding the access to private keys.
type SecretWallet struct {
	keystore                 storage.Store
	didstore                 storage.Store
	inboundTransportEndpoint string
}

// New return new instance of wallet implementation
func New(ctx provider) (*SecretWallet, error) {
	ks, err := ctx.StorageProvider().OpenStore(keyStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", keyStoreNamespace, err)
	}

	ds, err := ctx.StorageProvider().OpenStore(didStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", didStoreNamespace, err)
	}

	return &SecretWallet{keystore: ks, didstore: ds, inboundTransportEndpoint: ctx.InboundTransportEndpoint()}, nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (w *SecretWallet) CreateEncryptionKey() (string, error) {
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
func (w *SecretWallet) CreateSigningKey() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to GenerateKey: %w", err)
	}
	base58Pub := base58.Encode(pub[:])
	// TODO - need to encrypt the priv before putting them in the store.
	if e := persist(w.keystore, base58Pub, &cryptoutil.KeyPair{Pub: pub[:], Priv: priv[:]}); e != nil {
		return "", e
	}

	// generate the corresponding encryption keypair for any signing keypair
	_, err = w.convertToEncryptionKey(pub)
	if err != nil {
		return "", err
	}

	return base58Pub, nil
}

// convertToEncryptionKey converts an ed25519 keypair present in the wallet,
// persists the resulting keypair, and returns the result public key.
func (w *SecretWallet) convertToEncryptionKey(key []byte) ([]byte, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(key)
	if err != nil {
		return nil, err
	}
	encPubB58 := base58.Encode(encPub)

	keyB58 := base58.Encode(key)
	kp, err := w.GetKey(keyB58)
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
func (w *SecretWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	keyPair, err := w.GetKey(fromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return ed25519signature2018.New().Sign(keyPair.Priv, message)
}

// Close wallet
func (w *SecretWallet) Close() error {
	return nil
}

// CreateDID returns new DID Document
func (w *SecretWallet) CreateDID(method string, opts ...didcreator.DocOpts) (*did.Doc, error) {
	docOpts := &didopts.CreateDIDOpts{}
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
func (w *SecretWallet) GetDID(id string) (*did.Doc, error) {
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

// GetKey gets the keypair associated to the given pubkey
func (w *SecretWallet) GetKey(pub string) (*cryptoutil.KeyPair, error) {
	bytes, err := w.keystore.Get(pub)
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

// PutKey persists a keypair in the keystore
func (w *SecretWallet) PutKey(pub string, pair *cryptoutil.KeyPair) error {
	return persist(w.keystore, pub, pair)
}

// AttachCryptoOperator attaches a crypto operator to this wallet, so the operator can use its private keys.
func (w *SecretWallet) AttachCryptoOperator(cryptoOp operator.CryptoOperator) error {
	if cryptoOp == nil {
		return fmt.Errorf("cannot attach nil crypto operator")
	}
	return cryptoOp.InjectKeyHolder(w)
}

// DeriveKEK will derive an ephemeral symmetric key (kek) using a private key fetched from
// the wallet corresponding to fromPubKey and derived with toPubKey
// This implementation is for curve 25519 only
func (w *SecretWallet) DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	if fromPubKey == nil || toPubKey == nil {
		return nil, cryptoutil.ErrInvalidKey
	}
	fromPrivKey := new([chacha.KeySize]byte)
	copy(fromPrivKey[:], fromPubKey)

	// get keypair from wallet store
	walletKeyPair, err := w.GetKey(base58.Encode(fromPubKey))
	if err != nil {
		return nil, fmt.Errorf("failed from GetKey: %w", err)
	}
	copy(fromPrivKey[:], walletKeyPair.Priv)

	toKey := new([chacha.KeySize]byte)
	copy(toKey[:], toPubKey)
	return cryptoutil.Derive25519KEK(alg, apu, fromPrivKey, toKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the wallet
func (w *SecretWallet) FindVerKey(candidateKeys []string) (int, error) {
	for i, key := range candidateKeys {
		_, err := w.GetKey(key)
		if err != nil {
			if errors.Is(err, cryptoutil.ErrKeyNotFound) {
				continue
			}
			return -1, fmt.Errorf("failed from GetKey: %w", err)
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

func (w *SecretWallet) buildPeerDIDDoc(base58PubKey string, docOpts *didopts.CreateDIDOpts) (*did.Doc, error) {
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
	if docOpts.ServiceType != "" {
		// Service endpoints
		service = []did.Service{
			{
				ID:              "#agent",
				Type:            docOpts.ServiceType,
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
