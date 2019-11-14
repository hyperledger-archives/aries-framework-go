/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	keyStoreNamespace      = "keystore"
	metadataStoreNamespace = "metadatastore"
)

// provider contains dependencies for the base KMS and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
}

// BaseKMS Base Key Management Service implementation
type BaseKMS struct {
	keystore      storage.Store
	metadatastore storage.Store
}

// New return new instance of KMS implementation
func New(ctx provider) (*BaseKMS, error) {
	ks, err := ctx.StorageProvider().OpenStore(keyStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", keyStoreNamespace, err)
	}

	// TODO create a new/different StoreProvider for metadatastore
	ms, err := ctx.StorageProvider().OpenStore(metadataStoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to OpenStore for '%s', cause: %w", metadataStoreNamespace, err)
	}

	return &BaseKMS{keystore: ks, metadatastore: ms}, nil
}

// CreateKeySet creates a new public/private encryption and signature keys set and stores them in the KMS store.
// returns:
// 		string: key set ID of the marshaled cryptoutil.KeySet stored in the KMS store
//		string: base58 encoding of the public signature key
//		error: in case of errors
func (w *BaseKMS) CreateKeySet() (string, string, error) {
	// TODO - need to encrypt the encPriv and sigPriv before putting them in the store.
	sigPubKey, sigPrivKey, err := createAndStoreSigKeys(w.keystore)
	if err != nil {
		return "", "", err
	}

	encPubKey, encPrivKey, err := createAndStoreEncKeys(w.keystore, sigPubKey, sigPrivKey)
	if err != nil {
		return "", "", err
	}

	keySet := buildKeySetWithIDs(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	if er := persist(w.metadatastore, keySet.ID, keySet); er != nil {
		// TODO delete keys from keystore if keyset failed to store in metadatastore
		// 		to treat the whole function as an atomic operation
		return "", "", er
	}

	sigKeySetID := keySet.ID

	// create a second KeySet where the ID is set using the encryption Public Key to allow cross referencing
	// using an encryption key (useful during Crypter.Decrypt() where an envelope has only encryption keys)
	keySet = buildKeySetWithIDs(sigPubKey, encPubKey)
	// reset ID to hash of public encryption key instead of signature's for this second keyset
	h := sha256.Sum256([]byte(encPubKey.Value))

	keySet.ID = base64.RawURLEncoding.EncodeToString(h[:])
	if er := persist(w.metadatastore, keySet.ID, keySet); er != nil {
		// TODO delete keys from keystore if keyset failed to store in metadatastore
		// 		to treat the whole function as an atomic operation
		return "", "", er
	}

	// the second keySet is not to be referenced, it's only a helper to resolve a public signing key from an encrytion
	// key. Hence we return the first (official) KeySetID.
	return sigKeySetID, sigPubKey.Value, nil
}

// buildKeySetWithIDs will build a KeySet instance using the list of keys IDs only, no Values or other fields will be
// set. This utility function will help build a KeySet with reference IDs only to be stored in metadatastore.
// Therefore, no raw key values is assigned to KeySet in this function. It can be directly JSON marshalled and
// safely stored as is.
//
// The first key in the list is supposed to be the public signature key which represents the primary key.
// The key ID of the keySet will be the base64 encoding of the sha256 hashing of this first key.
func buildKeySetWithIDs(keys ...*cryptoutil.Key) cryptoutil.KeySet {
	keysID := []cryptoutil.Key{}
	for _, k := range keys {
		keysID = append(keysID, cryptoutil.Key{ID: k.ID})
	}
	// build the keySet ID
	h := sha256.Sum256([]byte(keys[0].Value)) // hash the key of the first key (will be primaryKey as anchor ID)
	id := base64.RawURLEncoding.EncodeToString(h[:])

	// now create the KeySet
	ks := cryptoutil.KeySet{
		ID:         id,
		PrimaryKey: cryptoutil.Key{ID: keys[0].ID}, // primaryKey should be signature public key
		Keys:       keysID,
	}

	return ks
}

// hashKeyID will hash the baseKeyID based on the key type (capability 'isSig': sig/enc and scope 'isPub': priv/pub)
// It is important that baseKeyID is the public signature key value. This will allow to derive other keys IDs in a
// deterministic fashion from the keystore.
// It will append s or e for signature or encryption, then p or s for public or secret (private)
// Note: baseKeyID value must be the raw bytes of the (signature public) key
func hashKeyID(baseKeyID []byte, isPub, isSig bool) string {
	id := [34]byte{}
	h := sha256.Sum256([]byte(base58.Encode(baseKeyID)))

	copy(id[:32], h[:])

	if isSig {
		id[32] = 's'
	} else {
		id[32] = 'e'
	}

	if isPub {
		id[33] = 'p'
	} else {
		id[33] += 's'
	}

	return base64.RawURLEncoding.EncodeToString(id[:])
}

// MockKeyID is used to mock a KeyID for testing and should not be used outside of tests
func MockKeyID(baseKeyID []byte, isPub, isSig bool) string {
	return hashKeyID(baseKeyID, isPub, isSig)
}

// hashKeySetID will hash primaryKeyID and base64 encode it.
// the returning value will be set in KeySet.ID
// the argument primaryKeyID should be from KeySet.PrimaryKey.Value
func hashKeySetID(primaryKeyID []byte) string {
	h := sha256.Sum256([]byte(base58.Encode(primaryKeyID)))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// MockKeySetID is used to mock KeySetID for testing and should not be used outside of tests
func MockKeySetID(primaryKeyID []byte) string {
	return hashKeySetID(primaryKeyID)
}

// newKey will create a new Key instance with baseKeyID as a reference for a new derived ID (via hashKeyID func).
// rawKey is the raw key value, it will be saved as base58 encoded string in SimpleyKey.Value
func newKey(baseKeyID, rawKey []byte, isPub, isSig bool) *cryptoutil.Key {
	id := hashKeyID(baseKeyID, isPub, isSig)

	alg := cryptoutil.Curve25519
	cpy := cryptoutil.Encryption

	if isSig {
		alg = cryptoutil.EdDSA
		cpy = cryptoutil.Signature
	}

	return &cryptoutil.Key{
		ID:         id,
		Value:      base58.Encode(rawKey),
		Capability: cpy,
		Alg:        alg,
	}
}

// createAndStoreEncKeys will convert sigKp into an encKeyPair - for now it's a key conversion operation.
// it can be modified to be generated independently - this has implications on the KMS store and the Packager/Crypter
// as they use Signature keys as arguments and convert them to Encryption keys for Pack/Unpack.
func createAndStoreEncKeys(keystore storage.Store, sigPubKey, sigPrvKey *cryptoutil.Key) (*cryptoutil.Key,
	*cryptoutil.Key, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(base58.Decode(sigPubKey.Value))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create encPub: %w", err)
	}

	encPriv, err := cryptoutil.SecretEd25519toCurve25519(base58.Decode(sigPrvKey.Value))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create encPriv: %w", err)
	}

	sigPubID := base58.Decode(sigPubKey.Value)
	// ID is sigPubKey appended with 'ep' for public key or 'es' for private key
	pubKey := newKey(sigPubID, encPub, true, false)

	err = persist(keystore, pubKey.ID, pubKey)
	if err != nil {
		return nil, nil, err
	}
	//  pass in sigPubID as keyID to newKey() as it will generate a new keyID for this privKey (derived from sigPub)
	privKey := newKey(sigPubID, encPriv, false, false)

	err = persist(keystore, privKey.ID, privKey)
	if err != nil {
		// TODO delete pubKey from store (once Store.Delete() is added)
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

func createAndStoreSigKeys(keystore storage.Store) (*cryptoutil.Key, *cryptoutil.Key, error) {
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Generate SigKeyPair: %w", err)
	}

	pubKey := newKey(sigPub[:], sigPub, true, true)

	err = persist(keystore, pubKey.ID, pubKey)
	if err != nil {
		return nil, nil, err
	}
	// pass in sigPubID as keyID to newKey() as it will generate a new keyID for this privKey (derived from sigPub)
	privKey := newKey(sigPub[:], sigPriv, false, true)

	err = persist(keystore, privKey.ID, privKey)
	if err != nil {
		// TODO delete pubKey from store (once Store.Delete() is added)
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

// ConvertToEncryptionKey converts an ed25519 keys present in the KMS into curve25519 encryption keys,
// persists the resulting keys to keystore and keySet to metadatastore then returns the resulting public encryption key.
func (w *BaseKMS) ConvertToEncryptionKey(verKey []byte) ([]byte, error) {
	encPub, err := cryptoutil.PublicEd25519toCurve25519(verKey)
	if err != nil {
		return nil, err
	}

	sigPrivKeyID := hashKeyID(verKey, false, true)

	sigPrivKey, err := w.getKey(sigPrivKeyID)
	if err != nil {
		return nil, err
	}

	encPriv, err := cryptoutil.SecretEd25519toCurve25519(base58.Decode(sigPrivKey.Value))
	if err != nil {
		return nil, err
	}

	// store verKey (public signature key)
	sigPubKey := newKey(verKey, verKey, true, true)

	err = persist(w.keystore, sigPubKey.ID, sigPubKey)
	if err != nil {
		return nil, err
	}

	encPubKey := newKey(verKey, encPub, true, false)

	err = persist(w.keystore, encPubKey.ID, encPubKey)
	if err != nil {
		return nil, err
	}

	encPrivKey := newKey(verKey, encPriv, false, false)

	err = persist(w.keystore, encPrivKey.ID, encPrivKey)
	if err != nil {
		return nil, err
	}

	keySet := buildKeySetWithIDs(sigPubKey, sigPrivKey, encPubKey, encPrivKey)
	if er := persist(w.metadatastore, keySet.ID, keySet); er != nil {
		// TODO delete keys from keystore if keyset failed to store in metadatastore
		// 		to treat the whole function as an atomic operation
		return nil, er
	}

	// create a second KeySet where the ID is set using the public encryption key to allow cross referencing
	// using an encryption key (useful during Crypter.Decrypt() where an envelope has only encryption keys)
	keySet = buildKeySetWithIDs(sigPubKey, encPubKey)
	// reset ID to hash of public encryption key instead of signature's for this second keyset
	h := sha256.Sum256([]byte(encPubKey.Value))
	keySet.ID = base64.RawURLEncoding.EncodeToString(h[:])

	if er := persist(w.metadatastore, keySet.ID, keySet); er != nil {
		// TODO delete keys from keystore if keyset failed to store in metadatastore - atomic operation
		return nil, er
	}

	return encPub, nil
}

// SignMessage sign a message using the private key associated with a given verification key (base58 encoded).
func (w *BaseKMS) SignMessage(message []byte, fromVerKeyB58 string) ([]byte, error) {
	// fetch private signature Key from keystore
	// by first deriving the private key ID using fromVerKey
	fromVerPrivKey := hashKeyID(base58.Decode(fromVerKeyB58), false, true)

	// then querying the store
	privKey, err := w.getKey(fromVerPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	return ed25519signature2018.New().Sign(base58.Decode(privKey.Value), message)
}

// Close the KMS
func (w *BaseKMS) Close() error {
	return nil
}

// getKeySet get the corresponding KeySet from metadatastore for keySetID
func (w *BaseKMS) getKeySet(keySetID string) (*cryptoutil.KeySet, error) {
	// KeySet ID is either encryption or signature public key
	bytes, err := w.metadatastore.Get(keySetID)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, cryptoutil.ErrKeyNotFound
		}

		return nil, err
	}

	// unmarshal and return KeySet as is (this KeySet has only reference IDs for keys, not real values)
	var key cryptoutil.KeySet
	if err := json.Unmarshal(bytes, &key); err != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", err)
	}

	return &key, nil
}

// getKey gets Key for the given keyID from keystore
func (w *BaseKMS) getKey(keyID string) (*cryptoutil.Key, error) {
	bytes, err := w.keystore.Get(keyID)
	if err != nil {
		if errors.Is(storage.ErrDataNotFound, err) {
			return nil, cryptoutil.ErrKeyNotFound
		}

		return nil, err
	}

	var key cryptoutil.Key
	if e := json.Unmarshal(bytes, &key); e != nil {
		return nil, fmt.Errorf("failed unmarshal to key struct: %w", e)
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

	// fetch private encryption Key from keystore
	// by first deriving the private encryption key ID using fromPubKey
	privKeyID := hashKeyID(fromPubKey, false, false)

	// then getting the key from keystore
	privKey, err := w.getKey(privKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed from getKey: %w", err)
	}

	copy(fromPrivKey[:], base58.Decode(privKey.Value))

	toKey := new([chacha.KeySize]byte)
	copy(toKey[:], toPubKey)

	return cryptoutil.Derive25519KEK(alg, apu, fromPrivKey, toKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the KMS
func (w *BaseKMS) FindVerKey(candidateKeys [][]byte) (int, error) {
	for i, key := range candidateKeys {
		// hash keySet ID
		k := hashKeySetID(key)

		// find if the encryption key has a matching KeySet (ie key belong to KMS)
		_, err := w.getKeySet(k)
		if err != nil {
			if errors.Is(err, cryptoutil.ErrKeyNotFound) {
				continue
			}

			return -1, fmt.Errorf("failed from getKeySet: %w", err)
		}
		// Currently chooses the first usable key, but could use different logic (eg, priorities)
		return i, nil
	}

	return -1, cryptoutil.ErrKeyNotFound
}

// FindVerKeyFromEncryptionKeys selects an encryption key which is present in candidateEncKeys that is present in
// the KMS then returns the selected index and the corresponding signing key.
func (w *BaseKMS) FindVerKeyFromEncryptionKeys(candidateEncKeys [][]byte) (int, string, error) {
	for i, key := range candidateEncKeys {
		hk := hashKeySetID(key)

		// find if the encryption key has a matching KeySet (ie key belong to KMS)
		ks, err := w.getKeySet(hk)
		if err != nil {
			if errors.Is(err, cryptoutil.ErrKeyNotFound) {
				continue
			}

			return -1, "", fmt.Errorf("failed from getKeySet: %w", err)
		}

		// Currently chooses the first usable key, but could use different logic (eg, priorities)
		// since the KeySets fetched in this function are queried by encryption key IDs, their PrimaryKey represents
		// the corresponding public signature key, extract its ID and query the keystore to get its value.
		verKeyID := ks.PrimaryKey.ID

		verKey, err := w.getKey(verKeyID)
		if err != nil {
			return -1, "", err
		}

		return i, verKey.Value, nil
	}

	return -1, "", cryptoutil.ErrKeyNotFound
}

// persist marshals value and saves it in store for given key
// this is a general DB (ADD/UPDATE) operation.
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

// GetEncryptionKey will return the raw public encryption key corresponding to the raw public verKey argument
func (w *BaseKMS) GetEncryptionKey(verKey []byte) ([]byte, error) {
	// the corresponding encryption public key ID
	encKeyID := hashKeyID(verKey, true, false)

	encKey, err := w.getKey(encKeyID)
	if err != nil {
		return nil, err
	}

	return base58.Decode(encKey.Value), nil
}
