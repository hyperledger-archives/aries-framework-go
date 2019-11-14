/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestBaseKMS_New(t *testing.T) {
	t.Run("test error from OpenStore for keystore", func(t *testing.T) {
		const errMsg = "error from OpenStore"
		_, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf(errMsg)}))
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestBaseKMS_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		ksID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, ksID)
		require.NotEmpty(t, sigPubKeyB58)
		ks, err := k.getKeySet(ksID)
		require.NoError(t, err)
		require.NotEmpty(t, ks)
		require.NotEmpty(t, ks.PrimaryKey)
		require.Equal(t, 4, len(ks.Keys), "a new KeySet must have a preset # of keys")
	})

	t.Run("test error from CreateKeySet", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}}))
		require.NoError(t, err)
		_, _, err = k.CreateKeySet()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})

	t.Run("test error from getKey and getKeySet", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte), ErrGet: fmt.Errorf("get error"),
		}}))
		require.NoError(t, err)
		ksID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		_, err = k.getKeySet(ksID)
		require.Contains(t, err.Error(), "get error")
		_, err = k.getKey(hashKeySetID(base58.Decode(sigPubKeyB58)))
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("test error from createAndStoreEncKeys", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		keySetID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, keySetID)
		ks, err := k.getKeySet(keySetID)
		require.NoError(t, err)
		pubSigKey, privSigKey, err := k.getSigKeys(ks.Keys)
		require.NoError(t, err)
		require.NotEmpty(t, pubSigKey)
		require.NotEmpty(t, privSigKey)
		require.Equal(t, pubSigKey.Value, sigPubKeyB58)

		// should pass with valid signature keys
		encPubKey, encPrivKey, err := createAndStoreEncKeys(k.keystore, pubSigKey, privSigKey)
		require.NoError(t, err)
		require.NotEmpty(t, encPubKey)
		require.NotEmpty(t, encPrivKey)

		// now break a key to force an error
		tmp := pubSigKey
		pubSigKey.Value += "*"
		encPubKey, encPrivKey, err = createAndStoreEncKeys(k.keystore, pubSigKey, privSigKey)
		require.Error(t, err)
		require.Empty(t, encPubKey)
		require.Empty(t, encPrivKey)

		// now test with nil private signature key
		privSigKey = nil
		pubSigKey = tmp
		encPubKey, encPrivKey, err = createAndStoreEncKeys(k.keystore, pubSigKey, privSigKey)
		require.Error(t, err)
		require.Empty(t, encPubKey)
		require.Empty(t, encPrivKey)
	})

	t.Run("test GetEncryption Key", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		keySetID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, keySetID)
		// test with empty signature key
		encK, err := k.GetEncryptionKey([]byte{})
		require.Error(t, err)
		require.Empty(t, encK)

		// get the above created keySet from metadatastore
		ks, err := k.getKeySet(keySetID)
		require.NoError(t, err)
		// get corresponding signature subkeys of this keyset from keystore
		pubSigKey, privSigKey, err := k.getSigKeys(ks.Keys)
		require.NoError(t, err)
		require.NotEmpty(t, pubSigKey)
		require.NotEmpty(t, privSigKey)
		require.Equal(t, pubSigKey.Value, sigPubKeyB58)
		// now get corresponding encryption subkeys of this keyset from keystore
		pubEncKey, privSEncKey, err := k.getEncKeys(ks.Keys)
		require.NoError(t, err)
		require.NotEmpty(t, pubEncKey)
		require.NotEmpty(t, privSEncKey)

		// finally test with real signature key and make sure encryption key is equal to the one found in the keystore
		encK, err = k.GetEncryptionKey(base58.Decode(pubSigKey.Value))
		require.NoError(t, err)
		require.Equal(t, pubEncKey.Value, base58.Encode(encK))
	})
}

// utility function used in tests only to get signature keys from a list of Key - can be moved to kms.go if needed
// keys is usually a list of sub keys in a keySet
func (w *BaseKMS) getSigKeys(keys []cryptoutil.Key) (*cryptoutil.Key, *cryptoutil.Key, error) {
	var pubKey, privKey *cryptoutil.Key

	for _, key := range keys {
		id, err := base64.RawURLEncoding.DecodeString(key.ID)
		if err != nil {
			return nil, nil, err
		}

		idStr := string(id)
		if strings.HasSuffix(idStr, "sp") {
			pubKey, err = w.getKey(key.ID)
			if err != nil {
				if errors.Is(storage.ErrDataNotFound, err) {
					continue
				}

				return nil, nil, err
			}
		} else if strings.HasSuffix(idStr, "ss") {
			privKey, err = w.getKey(key.ID)
			if err != nil {
				if errors.Is(storage.ErrDataNotFound, err) {
					continue
				}

				return nil, nil, err
			}
		}
	}

	if !verifyKeys(pubKey, privKey) {
		return nil, nil, storage.ErrDataNotFound
	}

	return pubKey, privKey, nil
}

func verifyKeys(pubKey, privKey *cryptoutil.Key) bool {
	if pubKey == nil || privKey == nil {
		return false
	}

	return true
}

// utility function used in tests only to get encryption keys from a list of Key -can be moved to kms.go if needed
// keys is usually a list of sub keys in a keySet
func (w *BaseKMS) getEncKeys(keys []cryptoutil.Key) (*cryptoutil.Key, *cryptoutil.Key, error) {
	var pubKey, privKey *cryptoutil.Key

	for _, key := range keys {
		id, err := base64.RawURLEncoding.DecodeString(key.ID)
		if err != nil {
			return nil, nil, err
		}

		idStr := string(id)
		if strings.HasSuffix(idStr, "ep") {
			pubKey, err = w.getKey(key.ID)
			if err != nil {
				if errors.Is(storage.ErrDataNotFound, err) {
					continue
				}

				return nil, nil, err
			}
		} else if strings.HasSuffix(idStr, "es") {
			privKey, err = w.getKey(key.ID)
			if err != nil {
				if errors.Is(storage.ErrDataNotFound, err) {
					continue
				}
				return nil, nil, err
			}
		}
	}

	if !verifyKeys(pubKey, privKey) {
		return nil, nil, storage.ErrDataNotFound
	}

	return pubKey, privKey, nil
}

func TestBaseKMS_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{}))
		require.NoError(t, err)
		require.NoError(t, k.Close())
	})
}

func TestBaseKMS_SignMessage(t *testing.T) {
	t.Run("test key not found", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		_, err = k.SignMessage(nil, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not found")
	})

	t.Run("test success", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		// first create a keyset
		keySetID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, keySetID)

		// get the above created keySet from metadatastore
		ks, err := k.getKeySet(keySetID)
		require.NoError(t, err)
		// get corresponding signature subkeys of this keyset from keystore
		pubSigKey, privSigKey, err := k.getSigKeys(ks.Keys)
		require.NoError(t, err)
		require.NotEmpty(t, pubSigKey)
		require.NotEmpty(t, privSigKey)
		require.Equal(t, pubSigKey.Value, sigPubKeyB58)
		t.Logf("pubSigKey id is: %v", pubSigKey.ID)
		t.Logf("privSigKey id is: %v", privSigKey.ID)

		// now test Signing a message with the public signature key value
		// which will be cross referenced internally in the KMS to fetch the private key for signing
		testMsg := []byte("hello")
		signature, err := k.SignMessage(testMsg, pubSigKey.Value)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// verify signature directly (with the public signature key)
		err = ed25519signature2018.New().Verify(base58.Decode(pubSigKey.Value), testMsg, signature)
		require.NoError(t, err)
	})
}

func TestBaseKMS_ConvertToEncryptionKey(t *testing.T) {
	t.Run("Success: generate and convert a signing key", func(t *testing.T) {
		k, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{},
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, k)

		// first create a keyset
		keySetID, sigPubKeyB58, err := k.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, keySetID)

		// get the above created keySet from metadatastore
		ks, err := k.getKeySet(keySetID)
		require.NoError(t, err)
		// get corresponding signature subkeys of this keyset from keystore
		pubSigKey, privSigKey, err := k.getSigKeys(ks.Keys)
		require.NoError(t, err)
		require.NotEmpty(t, pubSigKey)
		require.NotEmpty(t, privSigKey)
		require.Equal(t, pubSigKey.Value, sigPubKeyB58)

		_, err = k.ConvertToEncryptionKey(base58.Decode(pubSigKey.Value))
		require.NoError(t, err)
	})

	t.Run("Fail: convert keys with invalid pub key", func(t *testing.T) {
		k, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{},
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, k)

		rawKeyB58 := "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"
		rawKey := base58.Decode(rawKeyB58)
		pubKeyID := hashKeyID(rawKey, true, true)
		err = persist(k.keystore, pubKeyID, rawKeyB58+rawKeyB58)
		require.NoError(t, err)
		privKeyID := hashKeyID(rawKey, false, true)
		err = persist(k.keystore, privKeyID, rawKeyB58)
		require.NoError(t, err)

		_, err = k.ConvertToEncryptionKey(rawKey)
		require.EqualError(t, err, "error converting public key")
	})

	t.Run("Fail: convert keys with missing priv key", func(t *testing.T) {
		k, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{},
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, k)

		rawKeyB58 := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		rawKey := base58.Decode(rawKeyB58)
		pubKeyID := hashKeyID(rawKey, true, true)
		err = persist(k.keystore, pubKeyID, cryptoutil.Key{
			ID:         pubKeyID,
			Value:      rawKeyB58,
			Alg:        cryptoutil.EdDSA,
			Capability: cryptoutil.Signature,
		})
		require.NoError(t, err)
		privKeyID := hashKeyID(rawKey, false, true)
		err = persist(k.keystore, privKeyID, cryptoutil.Key{
			ID:         privKeyID, // Value is nil to trigger private key conversion error
			Alg:        cryptoutil.EdDSA,
			Capability: cryptoutil.Signature,
		})
		require.NoError(t, err)

		_, err = k.ConvertToEncryptionKey(rawKey)
		require.EqualError(t, err, "key is nil")
	})

	t.Run("Fail: convert keys with corrupt data stored", func(t *testing.T) {
		data := map[string][]byte{}
		rawKeyB58 := "CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz"
		rawKey := base58.Decode(rawKeyB58)
		data[hashKeyID(rawKey, true, true)] = []byte{0, 0, 0}  // corrupt public enc key
		data[hashKeyID(rawKey, false, true)] = []byte{0, 0, 0} // corrupt private enc key

		k, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: data,
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, k)

		_, err = k.ConvertToEncryptionKey(rawKey)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to key struct")
	})

	t.Run("Fail: convert keys with failure to persist in data store", func(t *testing.T) {
		data := map[string][]byte{}
		validSigPubKey := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		rawSigPubKey := base58.Decode(validSigPubKey)
		sigPubKey := cryptoutil.Key{
			ID:         hashKeyID(rawSigPubKey, true, true),
			Value:      base58.Encode(rawSigPubKey),
			Alg:        cryptoutil.EdDSA,
			Capability: cryptoutil.Signature,
		}
		sigPubKeyMarshalled, err := json.Marshal(sigPubKey)
		require.NoError(t, err)
		validSigPrivKey := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"
		rawSigPrivKey := base58.Decode(validSigPrivKey)
		sigPrivKey := cryptoutil.Key{
			ID:         hashKeyID(rawSigPubKey, false, true),
			Value:      base58.Encode(rawSigPrivKey),
			Alg:        cryptoutil.EdDSA,
			Capability: cryptoutil.Signature,
		}
		sigPrivKeyMarshalled, err := json.Marshal(sigPrivKey)
		require.NoError(t, err)
		data[sigPubKey.ID] = sigPubKeyMarshalled   // valid public signature key
		data[sigPrivKey.ID] = sigPrivKeyMarshalled // valid private signature key

		k, err := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store:  data,
					ErrPut: fmt.Errorf("put error"), // mocking persist error
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, k)

		_, err = k.ConvertToEncryptionKey(rawSigPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save in store")
	})
}

func TestBaseKMS_DeriveKEK(t *testing.T) {
	pk32, sk32, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kPub := cryptoutil.Key{
		ID:         hashKeyID(pk32[:], true, false),
		Value:      base58.Encode(pk32[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPriv := cryptoutil.Key{
		// hashing private key with public key to deterministically derive the private key ID
		// similar to newKey()
		ID:         hashKeyID(pk32[:], false, false),
		Value:      base58.Encode(sk32[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPubMarshaled, err := json.Marshal(kPub)
	require.NoError(t, err)
	kPrivMarshaled, err := json.Marshal(kPriv)
	require.NoError(t, err)

	pk32a, _, err := box.GenerateKey(rand.Reader)
	k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: map[string][]byte{
			kPub.ID:  kPubMarshaled,
			kPriv.ID: kPrivMarshaled,
		},
	}}))

	t.Run("test success", func(t *testing.T) {
		// test DeriveKEK from KMS where fromKey is a public key (private fromKey will be fetched from the KMS)
		require.NoError(t, err)
		kek, e := k.DeriveKEK(nil, nil, pk32[:], pk32a[:])
		require.NoError(t, e)
		require.NotEmpty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, sk32, pk32a)
		require.NoError(t, e)
		require.NotEmpty(t, kek)
	})

	t.Run("test failure fromKey empty and toKey not empty", func(t *testing.T) {
		// test DeriveKEK from KMS where fromKey is a public key (private fromKey will be fetched from the KMS)
		kek, e := k.DeriveKEK(nil, nil, nil, pk32a[:])
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, nil, pk32a)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)
	})

	t.Run("test failure fromKey not empty and toKey empty", func(t *testing.T) {
		// test DeriveKEK from KMS where fromKey is a public key (private fromKey will be fetched from the KMS)
		kek, e := k.DeriveKEK(nil, nil, pk32[:], nil)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, sk32, nil)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)
	})

	t.Run("test failure fromPubKey not found in KMS", func(t *testing.T) {
		// test DeriveKEK from KMS where fromKey is a public key (private fromKey will be fetched from the KMS)
		kek, e := k.DeriveKEK(nil, nil, pk32a[:], pk32[:])
		require.EqualError(t, e, "failed from getKey: "+cryptoutil.ErrKeyNotFound.Error())
		require.Empty(t, kek)
	})
}

func TestBaseKMS_FindVerKey(t *testing.T) {
	pk1, sk1, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kPub1 := cryptoutil.Key{
		ID:         hashKeyID(pk1[:], true, false),
		Value:      base58.Encode(pk1[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPriv1 := cryptoutil.Key{
		// hashing private key with public key to deterministically derive the private key ID
		// similar to newKey()
		ID:         hashKeyID(pk1[:], false, false),
		Value:      base58.Encode(sk1[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPub1Marshaled, err := json.Marshal(kPub1)
	require.NoError(t, err)
	kPriv1Marshaled, err := json.Marshal(kPriv1)
	require.NoError(t, err)

	pk2, sk2, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kPub2 := cryptoutil.Key{
		ID:         hashKeyID(pk2[:], true, false),
		Value:      base58.Encode(pk2[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPriv2 := cryptoutil.Key{
		// hashing private key with public key to deterministically derive the private key ID
		// similar to newKey()
		ID:         hashKeyID(pk2[:], false, false),
		Value:      base58.Encode(sk2[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPub2Marshaled, err := json.Marshal(kPub2)
	require.NoError(t, err)
	kPriv2Marshaled, err := json.Marshal(kPriv2)
	require.NoError(t, err)

	pk3, sk3, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kPub3 := cryptoutil.Key{
		ID:         hashKeyID(pk3[:], true, false),
		Value:      base58.Encode(pk3[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPriv3 := cryptoutil.Key{
		// hashing private key with public key to deterministically derive the private key ID
		// similar to newKey()
		ID:         hashKeyID(pk3[:], false, false),
		Value:      base58.Encode(sk3[:]),
		Alg:        cryptoutil.Curve25519,
		Capability: cryptoutil.Encryption,
	}
	kPub3Marshaled, err := json.Marshal(kPub3)
	require.NoError(t, err)
	kPriv3Marshaled, err := json.Marshal(kPriv3)
	require.NoError(t, err)

	// create keysets and store them in the same store (MockStore has only one store) it should be safe
	// to mock both keys sets and keys in the same store (real implementation has keystore and metadatastore)
	keySet1 := buildKeySetWithIDs(&kPub1, &kPriv1)
	keySet1Marshaled, err := json.Marshal(keySet1)
	require.NoError(t, err)

	keySet2 := buildKeySetWithIDs(&kPub2, &kPriv2)
	keySet2Marshaled, err := json.Marshal(keySet2)
	require.NoError(t, err)

	keySet3 := buildKeySetWithIDs(&kPub3, &kPriv3)
	keySet3Marshaled, err := json.Marshal(keySet3)
	require.NoError(t, err)

	k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: map[string][]byte{
			kPub1.ID:   kPub1Marshaled,
			kPriv1.ID:  kPriv1Marshaled,
			kPub2.ID:   kPub2Marshaled,
			kPriv2.ID:  kPriv2Marshaled,
			kPub3.ID:   kPub3Marshaled,
			kPriv3.ID:  kPriv3Marshaled,
			keySet1.ID: keySet1Marshaled,
			keySet2.ID: keySet2Marshaled,
			keySet3.ID: keySet3Marshaled,
		},
	}}))
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		candidateKeys := [][]byte{
			[]byte("somekey1"),
			[]byte("somekey2"),
			pk1[:],
		}
		i, e := k.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 2, i)
		candidateKeys = [][]byte{
			[]byte("somekey1"),
			pk1[:],
			[]byte("somekey2"),
		}
		i, e = k.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 1, i)
		candidateKeys = [][]byte{
			pk1[:],
			[]byte("somekey1"),
			[]byte("somekey2"),
		}
		i, e = k.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 0, i)
		candidateKeys = [][]byte{
			[]byte("somekey1"),
			pk2[:],
			[]byte("somekey2"),
			pk1[:],
		}
		i, e = k.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 1, i)
	})

	t.Run("fail: finding in empty candidateKeys", func(t *testing.T) {
		candidateKeys := [][]byte{}
		i, e := k.FindVerKey(candidateKeys)
		require.EqualError(t, e, cryptoutil.ErrKeyNotFound.Error())
		require.Equal(t, i, -1)
	})

	t.Run("fail: test candidate signing key is corrupt", func(t *testing.T) {
		ks, e := New(newMockKMSProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{hashKeySetID([]byte("testkey")): {0, 0, 1, 0, 0}},
				},
			}))
		require.NoError(t, e)
		_, e = ks.FindVerKey([][]byte{[]byte("not present"), []byte("testkey")})
		require.NotNil(t, e)
		require.Contains(t, e.Error(), "failed from getKeySet: failed unmarshal to key struct")
	})
}

func Test_Persist(t *testing.T) {
	store := &mockstorage.MockStore{
		Store: make(map[string][]byte),
	}

	const key = "sample-key"

	value := struct {
		Code    int32
		Message string
	}{
		Code:    1,
		Message: "message",
	}

	require.NoError(t, persist(store, key, value))

	result, err := store.Get(key)
	require.Nil(t, err)
	require.NotEmpty(t, result)

	invalidVal := struct {
		Code    int32
		Channel chan bool
	}{
		Code: 1,
	}

	err = persist(store, key, invalidVal)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to marshal")
}

func TestBaseKMS_FindVerKeyFromEncryptionKeys(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		// first create 2 keysets
		_, sigPubKey1B58, err := k.CreateKeySet()
		require.NoError(t, err)

		_, sigPubKey2B58, err := k.CreateKeySet()
		require.NoError(t, err)
		// second fetch encryption keys to call 'FindVerKeyFromEncryptionKeys()'
		encPubKey1ID := hashKeyID(base58.Decode(sigPubKey1B58), true, false)
		encPubKey2ID := hashKeyID(base58.Decode(sigPubKey2B58), true, false)
		encPubKey1, err := k.getKey(encPubKey1ID)
		require.NoError(t, err)
		encPubKey2, err := k.getKey(encPubKey2ID)
		require.NoError(t, err)

		i, keyB58, err := k.FindVerKeyFromEncryptionKeys([][]byte{
			base58.Decode(encPubKey1.Value),
			base58.Decode(encPubKey2.Value),
		})
		require.NoError(t, err)
		require.Equal(t, i, 0)
		require.Equal(t, sigPubKey1B58, keyB58)
	})

	t.Run("Fail: finding verKey in empty enc keys list", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		// first create 2 keysets
		_, _, err = k.CreateKeySet()
		require.NoError(t, err)

		_, _, err = k.CreateKeySet()
		require.NoError(t, err)

		i, _, err := k.FindVerKeyFromEncryptionKeys([][]byte{})
		require.EqualError(t, err, cryptoutil.ErrKeyNotFound.Error())
		require.Equal(t, i, -1)
	})

	t.Run("Fail: finding verKey with corrupt storage", func(t *testing.T) {
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("get error"),
			}}))
		require.NoError(t, err)
		// first create 2 keysets
		_, sigPubKey1B58, err := k.CreateKeySet()
		require.NoError(t, err)

		_, sigPubKey2B58, err := k.CreateKeySet()
		require.NoError(t, err)

		i, _, err := k.FindVerKeyFromEncryptionKeys([][]byte{
			base58.Decode(sigPubKey1B58),
			base58.Decode(sigPubKey2B58),
		})
		require.EqualError(t, err, "failed from getKeySet: get error")
		require.Equal(t, i, -1)
	})

	t.Run("Fail: finding verKey with missing KeySet", func(t *testing.T) {
		// first generate keys manually to omit storing KeySet
		sigPubKey1, sigPrivKey1, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		encPubKey1, encPrivKey1, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)

		sigPub1 := cryptoutil.Key{
			ID:         hashKeyID(sigPubKey1[:], true, true),
			Value:      base58.Encode(sigPubKey1[:]),
			Alg:        cryptoutil.Curve25519,
			Capability: cryptoutil.Encryption,
		}
		sigPriv1 := cryptoutil.Key{
			ID:         hashKeyID(sigPubKey1[:], false, true),
			Value:      base58.Encode(sigPrivKey1[:]),
			Alg:        cryptoutil.Curve25519,
			Capability: cryptoutil.Encryption,
		}
		encPub1 := cryptoutil.Key{
			ID:         hashKeyID(sigPubKey1[:], true, false),
			Value:      base58.Encode(encPubKey1[:]),
			Alg:        cryptoutil.Curve25519,
			Capability: cryptoutil.Encryption,
		}
		encPriv1 := cryptoutil.Key{
			ID:         hashKeyID(sigPubKey1[:], false, false),
			Value:      base58.Encode(encPrivKey1[:]),
			Alg:        cryptoutil.Curve25519,
			Capability: cryptoutil.Encryption,
		}
		sigPub1Marshaled, err := json.Marshal(sigPub1)
		require.NoError(t, err)
		sigPriv1Marshaled, err := json.Marshal(sigPriv1)
		require.NoError(t, err)
		encPub1Marshaled, err := json.Marshal(encPub1)
		require.NoError(t, err)
		encPriv1Marshaled, err := json.Marshal(encPriv1)
		require.NoError(t, err)

		require.NoError(t, err)
		k, err := New(newMockKMSProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					// mock keys without a KeySet in the storage to trigger missing keySet fetch
					// in FindVerKeyFromEncryptionKeys()
					sigPub1.ID:  sigPub1Marshaled,
					sigPriv1.ID: sigPriv1Marshaled,
					encPub1.ID:  encPub1Marshaled,
					encPriv1.ID: encPriv1Marshaled,
				},
			}}))
		require.NoError(t, err)

		i, keyB58, err := k.FindVerKeyFromEncryptionKeys([][]byte{encPubKey1[:]})
		require.EqualError(t, err, cryptoutil.ErrKeyNotFound.Error())
		require.Equal(t, i, -1)
		require.Empty(t, keyB58)
	})
}

func newMockKMSProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr}
}

// mockProvider mocks provider for KMS
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}
