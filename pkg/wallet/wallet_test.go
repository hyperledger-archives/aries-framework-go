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
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	serviceEndpoint    = "https://abc.example.com/83hfh37dj"
	serviceTypeDIDComm = "did-communication"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from GetStoreHandle", func(t *testing.T) {
		_, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{ErrGetStoreHandle: fmt.Errorf("error from GetStoreHandle")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error from GetStoreHandle")
	})
}

func TestBaseWallet_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		encKey, err := w.CreateEncryptionKey()
		require.NoError(t, err)
		require.NotEmpty(t, encKey)

		verKey, err := w.CreateSigningKey()
		require.NoError(t, err)
		require.NotEmpty(t, verKey)
	})

	t.Run("test error from persistKey", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}}))
		require.NoError(t, err)
		_, err = w.CreateEncryptionKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
		_, err = w.CreateSigningKey()
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

func TestBaseWallet_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{}))
		require.NoError(t, err)
		require.NoError(t, w.Close())
	})
}

func TestBaseWallet_UnpackMessage(t *testing.T) {
	t.Run("test failed from getKey", func(t *testing.T) {
		m := make(map[string][]byte)
		m["key1"] = nil
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: m, ErrGet: fmt.Errorf("get error"),
		}}))
		require.NoError(t, err)

		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w.crypter = crypter

		packMsg, err := json.Marshal(authcrypt.Envelope{
			Recipients: []authcrypt.Recipient{{Header: authcrypt.RecipientHeaders{KID: "key1"}}}})
		require.NoError(t, err)
		_, err = w.UnpackMessage(packMsg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("test failed to unmarshal encMessage", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		_, err = w.UnpackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal encMessage")
	})

	t.Run("test key not found", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w.crypter = crypter

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
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		decryptValue := func(envelope []byte, recipientKeyPair crypto.KeyPair) ([]byte, error) {
			return nil, fmt.Errorf("decrypt error")
		}
		e := func(payload []byte, sender crypto.KeyPair, recipients [][]byte) (bytes []byte, e error) {
			crypter, e := authcrypt.New(authcrypt.XC20P)
			require.NoError(t, e)
			return crypter.Encrypt(payload, sender, recipients)
		}
		mockCrypter := &didcomm.MockAuthCrypt{DecryptValue: decryptValue,
			EncryptValue: e}

		w.crypter = mockCrypter

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
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w.crypter = crypter

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
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)
		_, err = w.PackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "envelope argument is nil")
	})

	t.Run("test key not found error", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		crypter, err := authcrypt.New(authcrypt.XC20P)
		require.NoError(t, err)
		w.crypter = crypter

		_, err = w.PackMessage(&Envelope{Message: []byte("msg1"),
			FromVerKey: "key1",
			ToVerKeys:  []string{}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed from getKey")
	})

	t.Run("test encrypt failed", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))

		encryptValue := func(payload []byte, sender crypto.KeyPair, recipients [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("encrypt error")
		}

		w.crypter = &didcomm.MockAuthCrypt{EncryptValue: encryptValue}

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
	t.Run("test key not found error", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{}))
		require.NoError(t, err)
		_, err = w.SignMessage(nil, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not found")
	})
}

func TestBaseWallet_DecryptMessage(t *testing.T) {
	t.Run("test error not implemented", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{}))
		require.NoError(t, err)
		_, _, err = w.DecryptMessage(nil, "")
		require.Error(t, err)
	})
}

func TestBaseWallet_NewDID(t *testing.T) {
	const method = "example"

	storeProvider := &mockstorage.MockStoreProvider{Store: mockstorage.MockStore{
		Store: make(map[string][]byte),
	}}
	verifyDID := func(t *testing.T, didDoc *did.Doc) {
		require.NotEmpty(t, didDoc.Context)
		require.Equal(t, didDoc.Context[0], did.Context)
		require.NotEmpty(t, didDoc.Updated)
		require.NotEmpty(t, didDoc.Created)
		require.NotEmpty(t, didDoc.ID)
		require.NotEmpty(t, didDoc.PublicKey)

		for i, pubK := range didDoc.PublicKey {
			require.NotEmpty(t, pubK.ID)
			require.Equal(t, pubK.ID, fmt.Sprintf(didPKID, didDoc.ID, i+1))
			require.NotEmpty(t, pubK.Value)
			require.NotEmpty(t, pubK.Type)
			require.NotEmpty(t, pubK.Controller)
		}

		// test if corresponding secret is saved in wallet store
		store, err := storeProvider.GetStoreHandle()
		require.NoError(t, err)
		require.NotNil(t, store)

		pub := string(didDoc.PublicKey[0].Value)
		private, err := store.Get(pub)
		require.NoError(t, err)
		require.NotNil(t, private)

		// verify DID identifier
		require.Equal(t, didDoc.ID, fmt.Sprintf(didFormat, method, pub[:16]))

		// check that document has been signed
		require.True(t, len(didDoc.Proof) > 0)
		require.Equal(t, didDoc.Proof[0].Type, "Ed25519Signature2018")
		require.Equal(t, didDoc.ID+"#keys-2", didDoc.Proof[0].Creator)
		require.NotEmpty(t, didDoc.Proof[0].ProofValue)
	}

	t.Run("create new DID with service type", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.NoError(t, err)
		didDoc, err := w.CreateDID(method, WithServiceType(serviceTypeDIDComm))
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, didDoc)

		// verify services
		require.NotEmpty(t, didDoc.Service)
		for i, service := range didDoc.Service {
			require.NotEmpty(t, service.ID)
			require.Equal(t, service.ID, fmt.Sprintf(didServiceID, didDoc.ID, i+1))
			require.NotEmpty(t, service.Type)
			require.Equal(t, serviceTypeDIDComm, service.Type)
			require.NotEmpty(t, service.ServiceEndpoint)
			require.Equal(t, serviceEndpoint, service.ServiceEndpoint)
		}
	})

	t.Run("create new DID without service type", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.NoError(t, err)
		didDoc, err := w.CreateDID(method)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, didDoc)

		// verify services
		require.Empty(t, didDoc.Service)
	})
}

func TestSignDocumentError(t *testing.T) {
	context := &signer.Context{
		SignatureType: "Ed25519Signature2018",
	}

	signedDoc, err := signDocument(context, &did.Doc{})
	require.NotNil(t, err)
	require.Nil(t, signedDoc)
	require.Contains(t, err.Error(), "creator is missing")
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

func (m *mockProvider) InboundTransportEndpoint() string {
	return serviceEndpoint
}
