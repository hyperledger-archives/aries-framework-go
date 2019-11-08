/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	keyStoreNamespace = "keystore"
)

// provider contains dependencies for the base KMS and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
}

// BaseKMS Base Key Management Service implementation
type BaseKMS struct {
	keystore storage.Store
}

// New return new instance of KMS implementation
func New(ctx provider) (*BaseKMS, error) {
	ks, err := ctx.StorageProvider().OpenStore(keyStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", keyStoreNamespace, err)
	}

	return &BaseKMS{keystore: ks}, nil
}

// CreateKeySet creates a new public/private encryption and signature keypairs combo.
// returns:
// 		string: encryption key id base58 encoded of the marshaled cryptoutil.KayPairCombo stored in the KMS store
// 		string: signature key id base58 encoded of the marshaled cryptoutil.KayPairCombo stored in the KMS store
//		error: in case of errors
func (w *BaseKMS) CreateKeySet() (string, string, error) {
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
// the KMS store and the Packager/Packer as they use Signature keys as arguments and use the converted
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

// ConvertToEncryptionKey converts an ed25519 keypair present in the KMS,
// persists the resulting keypair, and returns the result public key.
func (w *BaseKMS) ConvertToEncryptionKey(verKey []byte) ([]byte, error) {
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
func (w *BaseKMS) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	kpc, err := w.getKeyPairSet(fromVerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return ed25519signature2018.New().Sign(kpc.SigKeyPair.Priv, message)
}

// Close the KMS
func (w *BaseKMS) Close() error {
	return nil
}

// getKeyPairSet get encryption & signature key pairs combo
func (w *BaseKMS) getKeyPairSet(verKey string) (*cryptoutil.MessagingKeys, error) {
	bytes, err := w.keystore.Get(verKey)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, cryptoutil.ErrKeyNotFound
		}

		return nil, err
	}

	var key cryptoutil.MessagingKeys

	err = json.Unmarshal(bytes, &key)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", err)
	}

	return &key, nil
}

// DeriveKEK will derive an ephemeral symmetric key (kek) using a private key fetched from
// the KMS corresponding to fromPubKey and derived with toPubKey
// This implementation is for curve 25519 only
func (w *BaseKMS) DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	if fromPubKey == nil || toPubKey == nil {
		return nil, cryptoutil.ErrInvalidKey
	}

	fromPrivKey := new([chacha.KeySize]byte)
	copy(fromPrivKey[:], fromPubKey)

	// get key pairs combo from KMS store
	kpc, err := w.getKeyPairSet(base58.Encode(fromPubKey))
	if err != nil {
		return nil, fmt.Errorf("failed from getKeyPairSet: %w", err)
	}

	copy(fromPrivKey[:], kpc.EncKeyPair.Priv)

	toKey := new([chacha.KeySize]byte)
	copy(toKey[:], toPubKey)

	return cryptoutil.Derive25519KEK(alg, apu, fromPrivKey, toKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the KMS
func (w *BaseKMS) FindVerKey(candidateKeys []string) (int, error) {
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

// GetEncryptionKey will return the public encryption key corresponding to the public verKey argument
func (w *BaseKMS) GetEncryptionKey(verKey []byte) ([]byte, error) {
	b58VerKey := base58.Encode(verKey)
	kpCombo, err := w.getKeyPairSet(b58VerKey)

	if err != nil {
		return nil, err
	}

	return kpCombo.EncKeyPair.Pub, nil
}
