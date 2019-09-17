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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto/jwe/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from GetStoreHandle", func(t *testing.T) {
		_, err := New(&mockstorage.MockStoreProvider{ErrGetStoreHandle: fmt.Errorf("error from GetStoreHandle")}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error from GetStoreHandle")
	})

}

func TestBaseWallet_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, nil)
		require.NoError(t, err)
		verKey, err := w.CreateKey()
		require.NoError(t, err)
		require.NotEmpty(t, verKey)

	})

	t.Run("test error from persistKey", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}}, nil)
		require.NoError(t, err)
		_, err = w.CreateKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestBaseWallet_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{}, nil)
		require.NoError(t, err)
		require.NoError(t, w.Close())
	})
}

func TestBaseWallet_UnpackMessage(t *testing.T) {
	t.Run("test failed from getKey", func(t *testing.T) {
		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		m := make(map[string][]byte)
		m["key1"] = nil
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: m, ErrGet: fmt.Errorf("get error"),
		}}, crypter)
		require.NoError(t, err)
		packMsg, err := json.Marshal(authcrypt.Envelope{Recipients: []authcrypt.Recipient{{Header: authcrypt.RecipientHeaders{KID: "key1"}}}})
		require.NoError(t, err)
		_, err = w.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("test failed to unmarshal encMessage", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, nil)
		require.NoError(t, err)
		_, err = w.UnpackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal encMessage")
	})

	t.Run("test key not found", func(t *testing.T) {
		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, crypter)
		require.NoError(t, err)

		pub1, priv1, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		base58FromVerKey := base58.Encode(pub1[:])
		require.NoError(t, w.persistKey(base58FromVerKey, &crypto.KeyPair{Pub: pub1[:],
			Priv: priv1[:]}))

		pub2, _, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)

		packMsg, err := w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58.Encode(pub2[:])}})
		require.NoError(t, err)

		_, err = w.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no corresponding recipient key found in")
	})

	t.Run("test decrypt failed", func(t *testing.T) {
		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, &didcomm.MockAuthCrypt{DecryptValue: func(envelope []byte, recipientKeyPair crypto.KeyPair) ([]byte, error) {
			return nil, fmt.Errorf("decrypt error")
		}, EncryptValue: func(payload []byte, sender crypto.KeyPair, recipients [][]byte) (bytes []byte, e error) {
			return crypter.Encrypt(payload, sender, recipients)
		}})
		require.NoError(t, err)

		pub1, priv1, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		base58FromVerKey := base58.Encode(pub1[:])
		require.NoError(t, w.persistKey(base58FromVerKey, &crypto.KeyPair{Pub: pub1[:],
			Priv: priv1[:]}))

		pub2, priv2, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, w.persistKey(base58.Encode(pub2[:]), &crypto.KeyPair{Pub: pub2[:],
			Priv: priv2[:]}))

		packMsg, err := w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58.Encode(pub2[:])}})
		require.NoError(t, err)

		_, err = w.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decrypt error")

	})
}

func TestBaseWallet_PackMessage(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, crypter)
		require.NoError(t, err)

		pub1, priv1, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		base58FromVerKey := base58.Encode(pub1[:])
		require.NoError(t, w.persistKey(base58FromVerKey, &crypto.KeyPair{Pub: pub1[:],
			Priv: priv1[:]}))

		pub2, priv2, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, w.persistKey(base58.Encode(pub2[:]), &crypto.KeyPair{Pub: pub2[:],
			Priv: priv2[:]}))

		packMsg, err := w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58.Encode(pub2[:])}})
		require.NoError(t, err)

		unpackMsg, err := w.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, []byte("msg1"), unpackMsg.Message)

	})

	t.Run("test envelope is nil", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, nil)
		require.NoError(t, err)
		_, err = w.PackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "envelope argument is nil")
	})

	t.Run("test key not found error", func(t *testing.T) {
		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, crypter)
		require.NoError(t, err)

		_, err = w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: "key1",
			ToVerKeys:  []string{}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed from getKey")
	})

	t.Run("test encrypt failed", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}, &didcomm.MockAuthCrypt{EncryptValue: func(payload []byte, sender crypto.KeyPair, recipients [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("encrypt error")
		}})
		require.NoError(t, err)

		pub1, priv1, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		base58FromVerKey := base58.Encode(pub1[:])
		require.NoError(t, w.persistKey(base58FromVerKey, &crypto.KeyPair{Pub: pub1[:],
			Priv: priv1[:]}))

		pub2, priv2, err := box.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, w.persistKey(base58.Encode(pub2[:]), &crypto.KeyPair{Pub: pub2[:],
			Priv: priv2[:]}))

		_, err = w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: base58FromVerKey,
			ToVerKeys:  []string{base58.Encode(pub2[:])}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "encrypt error")

	})
}

func TestBaseWallet_SignMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{}, nil)
		require.NoError(t, err)
		_, err = w.SignMessage(nil, "")
		require.Error(t, err)
	})
}

func TestBaseWallet_DecryptMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(&mockstorage.MockStoreProvider{}, nil)
		require.NoError(t, err)
		_, _, err = w.DecryptMessage(nil, "")
		require.Error(t, err)
	})
}
