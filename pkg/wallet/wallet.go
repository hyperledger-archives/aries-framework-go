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

// CreateKeySet creates a new public/private encryption and signature keypairs combo.
// returns:
// 		string: encryption key id base58 encoded of the marshaled cryptoutil.KayPairCombo stored in the wallet
// 		string: signature key id base58 encoded of the marshaled cryptoutil.KayPairCombo stored in the wallet
//		error: in case of errors
func (w *BaseWallet) CreateKeySet() (string, string, error) {
	// TODO - need to encrypt the encPriv and sigPriv before putting them in the store.
	sigKp, err := createSigKeyPair()
	if err != nil {
		return "", "", err
	}
	encKp, err := createEncKeyPair(sigKp)
	if err != nil {
		return "", "", err
	}
	encBase58Pub := base58.Encode(encKp.Pub)
	kpCombo := &cryptoutil.MessagingKeys{
		EncKeyPair: encKp,
		SigKeyPair: sigKp,
	}

	// TODO - need to encrypt kpCombo.sigKp.Priv and kpCombo.encKp.Priv before putting them in the store.
	if er := persist(w.keystore, encBase58Pub, kpCombo); er != nil {
		return "", "", er
	}

	// TODO - find a better way to point both signature and encryption public keys as keyIds to
	//  	the same kpCombo value in the store
	// for now the keypair combo is stored twice (once for encPubKey and once for sigPubKey)
	sigBase58Pub := base58.Encode(sigKp.Pub)
	if er := persist(w.keystore, sigBase58Pub, kpCombo); er != nil {
		return "", "", er
	}

	return encBase58Pub, sigBase58Pub, nil
}

// createEncKeyPair will convert sigKp into an encKeyPair - for now it's a key conversion operation.
// it can be modified to be generated independently from sigKp - this has implications on
// the wallet store and the Packager/Crypter as they use Signature keys as arguments and use the converted
//  to Encryption keys for Pack/Unpack.
func createEncKeyPair(sigKp *cryptoutil.SigKeyPair) (*cryptoutil.EncKeyPair, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(sigKp.Pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create encPub: %w", err)
	}
	encPriv, err := cryptoutil.SecretEd25519toCurve25519(sigKp.Priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create encPriv: %w", err)
	}
	return &cryptoutil.EncKeyPair{
		KeyPair: cryptoutil.KeyPair{Pub: encPub, Priv: encPriv},
		Alg:     cryptoutil.Curve25519,
	}, nil
}

func createSigKeyPair() (*cryptoutil.SigKeyPair, error) {
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to Generate SigKeyPair: %w", err)
	}

	return &cryptoutil.SigKeyPair{
		KeyPair: cryptoutil.KeyPair{
			Pub:  sigPub[:],
			Priv: sigPriv[:]},
		Alg: cryptoutil.EdDSA,
	}, nil
}

// ConvertToEncryptionKey converts an ed25519 keypair present in the wallet,
// persists the resulting keypair, and returns the result public key.
func (w *BaseWallet) ConvertToEncryptionKey(verKey []byte) ([]byte, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(verKey)
	if err != nil {
		return nil, err
	}
	encPubB58 := base58.Encode(encPub)

	sigPubB58 := base58.Encode(verKey)
	kpc, err := w.getKeyPairSet(sigPubB58)
	if err != nil {
		return nil, err
	}
	encPriv, err := cryptoutil.SecretEd25519toCurve25519(kpc.SigKeyPair.Priv)
	if err != nil {
		return nil, err
	}
	kpNew := &cryptoutil.MessagingKeys{
		EncKeyPair: &cryptoutil.EncKeyPair{KeyPair: cryptoutil.KeyPair{Priv: encPriv, Pub: encPub}},
		SigKeyPair: kpc.SigKeyPair,
	}
	err = persist(w.keystore, encPubB58, kpNew)
	if err != nil {
		return nil, err
	}
	// TODO duplicate MessagingKeys in store or use a metadata store to map sig->enc?
	// 		for now we're duplicating entries as we only have 'keystore' (update when 'metadatastore' is added)
	err = persist(w.keystore, sigPubB58, kpNew)
	if err != nil {
		return nil, err
	}
	return encPub, nil
}

// SignMessage sign a message using the private key associated with a given verification key.
func (w *BaseWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	kpc, err := w.getKeyPairSet(fromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	return ed25519signature2018.New().Sign(kpc.SigKeyPair.Priv, message)
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

	// Generate Encryption & Signing key pairs and store them in the wallet
	_, pubVerKey, err := w.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	var didDoc *did.Doc

	switch method {
	case peerDIDMethod:
		didDoc, err = w.buildPeerDIDDoc(pubVerKey, docOpts)
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

// getKeyPairSet get encryption & signature key pairs combo
func (w *BaseWallet) getKeyPairSet(verKey string) (*cryptoutil.MessagingKeys, error) {
	bytes, err := w.keystore.Get(verKey)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, cryptoutil.ErrKeyNotFound
		}
		return nil, err
	}
	var key cryptoutil.MessagingKeys
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

	// get key pairs combo from wallet store
	kpc, err := w.getKeyPairSet(base58.Encode(fromPubKey))
	if err != nil {
		return nil, fmt.Errorf("failed from getKeyPairSet: %w", err)
	}
	copy(fromPrivKey[:], kpc.EncKeyPair.Priv)

	toKey := new([chacha.KeySize]byte)
	copy(toKey[:], toPubKey)
	return cryptoutil.Derive25519KEK(alg, apu, fromPrivKey, toKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the wallet
func (w *BaseWallet) FindVerKey(candidateKeys []string) (int, error) {
	for i, key := range candidateKeys {
		_, err := w.getKeyPairSet(key)
		if err != nil {
			if errors.Is(err, cryptoutil.ErrKeyNotFound) {
				continue
			}
			return -1, fmt.Errorf("failed from getKeyPairSet: %w", err)
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

// GetEncryptionKey will return the public encryption key corresponding to the public verKey argument
func (w *BaseWallet) GetEncryptionKey(verKey []byte) ([]byte, error) {
	b58VerKey := base58.Encode(verKey)
	kpCombo, err := w.getKeyPairSet(b58VerKey)
	if err != nil {
		return nil, err
	}
	return kpCombo.EncKeyPair.Pub, nil
}
