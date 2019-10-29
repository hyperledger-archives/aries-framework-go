/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from OpenStore for keystore", func(t *testing.T) {
		const errMsg = "error from OpenStore"
		_, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf(errMsg)}))
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestBaseWallet_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		encKey, verKey, err := w.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, encKey)
		require.NotEmpty(t, verKey)
	})

	t.Run("test error from persistKey", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}}))
		require.NoError(t, err)
		_, _, err = w.CreateKeySet()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})

	t.Run("test error from createEncKeyPair", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		encKey, verKey, err := w.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, encKey)
		require.NotEmpty(t, verKey)
		kpb, err := w.getKeyPairSet(verKey)
		require.NoError(t, err)
		encKp, err := createEncKeyPair(kpb.SigKeyPair)
		require.NoError(t, err)
		require.NotEmpty(t, encKp)
		// now break keys to force an error
		tmp := kpb.SigKeyPair.Pub
		kpb.SigKeyPair.Pub = append(kpb.SigKeyPair.Pub, byte('*'))
		encKp, err = createEncKeyPair(kpb.SigKeyPair)
		require.Error(t, err)
		require.Empty(t, encKp)
		kpb.SigKeyPair.Priv = nil
		kpb.SigKeyPair.Pub = tmp
		encKp, err = createEncKeyPair(kpb.SigKeyPair)
		require.Error(t, err)
		require.Empty(t, encKp)
	})

	t.Run("test GetEncryption Key", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		encPubK, sigPubK, err := w.CreateKeySet()
		require.NoError(t, err)
		encK, err := w.GetEncryptionKey([]byte{})
		require.Error(t, err)
		require.Empty(t, encK)
		encK, err = w.GetEncryptionKey(base58.Decode(sigPubK))
		require.NoError(t, err)
		require.Equal(t, encPubK, base58.Encode(encK))
	})
}

func TestBaseWallet_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{}))
		require.NoError(t, err)
		require.NoError(t, w.Close())
	})
}

func TestBaseWallet_SignMessage(t *testing.T) {
	t.Run("test key not found", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		_, err = w.SignMessage(nil, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not found")
	})

	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			}}))
		require.NoError(t, err)
		_, fromVerKey, err := w.CreateKeySet()
		require.NoError(t, err)
		require.NotEmpty(t, fromVerKey)

		testMsg := []byte("hello")
		signature, err := w.SignMessage(testMsg, fromVerKey)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// verify signature
		err = ed25519signature2018.New().Verify(base58.Decode(fromVerKey), testMsg, signature)
		require.NoError(t, err)
	})
}

func TestBaseWallet_ConvertToEncryptionKey(t *testing.T) {
	t.Run("Success: generate and convert a signing key", func(t *testing.T) {
		w, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{},
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, w)

		_, pub, err := w.CreateKeySet()
		require.NoError(t, err)

		_, err = w.ConvertToEncryptionKey(base58.Decode(pub))
		require.NoError(t, err)
	})

	t.Run("Fail: convert keypair with invalid pub key", func(t *testing.T) {
		w, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{},
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, w)

		badkp := cryptoutil.KeyPair{
			Priv: base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV76ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"),
			Pub:  base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"),
		}

		err = persist(w.keystore, "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7", &badkp)
		require.NoError(t, err)

		_, err = w.ConvertToEncryptionKey(base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"))
		require.EqualError(t, err, "error converting public key")
	})

	t.Run("Fail: convert keypair with corrupt data stored", func(t *testing.T) {
		data := map[string][]byte{}
		data["CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz"] = []byte{0, 0, 0}

		w, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: data,
				},
			}))
		require.NoError(t, err)
		require.NotNil(t, w)

		_, err = w.ConvertToEncryptionKey(base58.Decode("CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to key struct")
	})
}

func TestBaseWallet_DeriveKEK(t *testing.T) {
	pk32, sk32, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kp := cryptoutil.KeyPair{Pub: pk32[:], Priv: sk32[:]}

	kpCombo := &cryptoutil.MessagingKeys{
		EncKeyPair: &cryptoutil.EncKeyPair{
			KeyPair: kp,
			Alg:     cryptoutil.Curve25519,
		},
		SigKeyPair: nil,
	}
	kpm, err := json.Marshal(kpCombo)
	require.NoError(t, err)

	pk32a, _, err := box.GenerateKey(rand.Reader)
	w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: map[string][]byte{
			base58.Encode(pk32[:]): kpm,
		},
	}}))

	t.Run("test success", func(t *testing.T) {
		// test DeriveKEK from wallet where fromKey is a public key (private fromKey will be fetched from the wallet)
		require.NoError(t, err)
		kek, e := w.DeriveKEK(nil, nil, pk32[:], pk32a[:])
		require.NoError(t, e)
		require.NotEmpty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, sk32, pk32a)
		require.NoError(t, e)
		require.NotEmpty(t, kek)
	})

	t.Run("test failure fromKey empty and toKey not empty", func(t *testing.T) {
		// test DeriveKEK from wallet where fromKey is a public key (private fromKey will be fetched from the wallet)
		kek, e := w.DeriveKEK(nil, nil, nil, pk32a[:])
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, nil, pk32a)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)
	})

	t.Run("test failure fromKey not empty and toKey empty", func(t *testing.T) {
		// test DeriveKEK from wallet where fromKey is a public key (private fromKey will be fetched from the wallet)
		kek, e := w.DeriveKEK(nil, nil, pk32[:], nil)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)

		// test Derive25519KEK from the util function where fromKey is a private key
		kek, e = cryptoutil.Derive25519KEK(nil, nil, sk32, nil)
		require.EqualError(t, e, cryptoutil.ErrInvalidKey.Error())
		require.Empty(t, kek)
	})

	t.Run("test failure fromPubKey not found in wallet", func(t *testing.T) {
		// test DeriveKEK from wallet where fromKey is a public key (private fromKey will be fetched from the wallet)
		kek, e := w.DeriveKEK(nil, nil, pk32a[:], pk32[:])
		require.EqualError(t, e, "failed from getKeyPairSet: "+cryptoutil.ErrKeyNotFound.Error())
		require.Empty(t, kek)
	})
}

func TestBaseWallet_FindVerKey(t *testing.T) {
	pk1, sk1, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kp := cryptoutil.KeyPair{Pub: pk1[:], Priv: sk1[:]}
	kpm1, err := json.Marshal(kp)
	require.NoError(t, err)

	pk2, sk2, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kp = cryptoutil.KeyPair{Pub: pk2[:], Priv: sk2[:]}
	kpm2, err := json.Marshal(kp)
	require.NoError(t, err)

	pk3, sk3, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kp = cryptoutil.KeyPair{Pub: pk3[:], Priv: sk3[:]}
	kpm3, err := json.Marshal(kp)
	require.NoError(t, err)

	w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: map[string][]byte{
			base58.Encode(pk1[:]): kpm1,
			base58.Encode(pk2[:]): kpm2,
			base58.Encode(pk3[:]): kpm3,
		},
	}}))
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		candidateKeys := []string{
			"somekey1",
			"somekey2",
			base58.Encode(pk1[:]),
		}
		i, e := w.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 2, i)
		candidateKeys = []string{
			"somekey1",
			base58.Encode(pk1[:]),
			"somekey2",
		}
		i, e = w.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 1, i)
		candidateKeys = []string{
			base58.Encode(pk1[:]),
			"somekey1",
			"somekey2",
		}
		i, e = w.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 0, i)
		candidateKeys = []string{
			"somekey1",
			base58.Encode(pk2[:]),
			"somekey2",
			base58.Encode(pk1[:]),
		}
		i, e = w.FindVerKey(candidateKeys)
		require.NoError(t, e)
		require.Equal(t, 1, i)
	})

	t.Run("test candidate signing key is corrupted", func(t *testing.T) {
		w, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{"testkey": {0, 0, 1, 0, 0}},
				},
			}))
		require.NoError(t, err)
		_, err = w.FindVerKey([]string{"not present", "testkey"})
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed from getKeyPairSet: failed unmarshal to key struct")
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

func newMockWalletProvider(storagePvdr *mockstorage.MockStoreProvider) *mockProvider {
	return &mockProvider{storagePvdr}
}

// mockProvider mocks provider for wallet
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}
