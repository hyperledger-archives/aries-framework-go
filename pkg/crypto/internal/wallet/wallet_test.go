/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	serviceEndpoint    = "sample-endpoint.com"
	serviceTypeDIDComm = "did-communication"
)

func TestBaseWallet_New(t *testing.T) {
	t.Run("test error from OpenStore for keystore", func(t *testing.T) {
		const errMsg = "error from OpenStore"
		_, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf(errMsg)}))
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
	t.Run("test error from OpenStore for did store", func(t *testing.T) {
		_, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{FailNameSpace: didStoreNamespace}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store for name space")
	})
}

func TestBaseWallet_CreateKey(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
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
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
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
		fromVerKey, err := w.CreateSigningKey()
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

		pub, err := w.CreateSigningKey()
		require.NoError(t, err)

		_, err = w.convertToEncryptionKey(base58.Decode(pub))
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

		_, err = w.convertToEncryptionKey(base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"))
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

		_, err = w.convertToEncryptionKey(base58.Decode("CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz"))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed unmarshal to key struct")
	})
}

func TestBaseWallet_DIDCreator(t *testing.T) {
	storeProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
		Store: make(map[string][]byte),
	}}
	verifyDID := func(t *testing.T, method string, didDoc *did.Doc) {
		require.NotEmpty(t, didDoc.Context)
		require.Equal(t, didDoc.Context[0], did.Context)
		require.NotEmpty(t, didDoc.Updated)
		require.NotEmpty(t, didDoc.Created)
		require.NotEmpty(t, didDoc.ID)
		require.NotEmpty(t, didDoc.PublicKey)

		for _, pubK := range didDoc.PublicKey {
			require.NotEmpty(t, pubK.ID)
			switch method {
			case peerDIDMethod:
				require.Equal(t, pubK.ID, string(pubK.Value)[0:7])
			default:
				require.Fail(t, "Invalid DID Method")
			}
			require.NotEmpty(t, pubK.Value)
			require.NotEmpty(t, pubK.Type)
			require.NotEmpty(t, pubK.Controller)
		}

		// test if corresponding secret is saved in wallet store
		store, err := storeProvider.OpenStore(keyStoreNamespace)
		require.NoError(t, err)
		require.NotNil(t, store)

		pub := string(didDoc.PublicKey[0].Value)
		private, err := store.Get(pub)
		require.Nil(t, err)
		require.NotNil(t, private)

		// verify DID identifier
		switch method {
		case peerDIDMethod:
			require.Equal(t, didDoc.ID[0:9], "did:peer:")
		default:
			require.Fail(t, "Invalid DID Method")
		}
	}

	t.Run("create/fetch Peer DID with service type", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.NoError(t, err)
		didDoc, err := w.CreateDID(peerDIDMethod, didcreator.WithServiceType(serviceTypeDIDComm))
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify services
		require.NotEmpty(t, didDoc.Service)
		for _, service := range didDoc.Service {
			require.NotEmpty(t, service.ID)
			require.Equal(t, "#agent", service.ID)
			require.NotEmpty(t, service.Type)
			require.Equal(t, serviceTypeDIDComm, service.Type)
			require.NotEmpty(t, service.ServiceEndpoint)
			require.Equal(t, serviceEndpoint, service.ServiceEndpoint)
		}

		result, err := w.GetDID(didDoc.ID)
		verifyDID(t, peerDIDMethod, didDoc)
		require.Nil(t, err)
		require.Equal(t, result.Service, didDoc.Service)
		require.Equal(t, result.PublicKey, didDoc.PublicKey)
	})

	t.Run("create new DID without service type", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.NoError(t, err)
		didDoc, err := w.CreateDID(peerDIDMethod)
		require.NoError(t, err)
		require.NotNil(t, didDoc)

		verifyDID(t, peerDIDMethod, didDoc)

		// verify services
		require.Empty(t, didDoc.Service)

		result, err := w.GetDID(didDoc.ID)
		verifyDID(t, peerDIDMethod, didDoc)
		require.Nil(t, err)
		require.Empty(t, result.Service)
		require.Equal(t, result.PublicKey, didDoc.PublicKey)
	})

	t.Run("try to get non existing DID", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.Nil(t, err)
		require.NotNil(t, w)

		result, err := w.GetDID("non-existing-did")
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Nil(t, result)
	})

	t.Run("failure while getting DID by ID", func(t *testing.T) {
		const errMsg = "sample-error-msg"
		mockStoreProvider := &mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store:  make(map[string][]byte),
			ErrPut: errors.New(errMsg),
			ErrGet: errors.New(errMsg),
		}}

		w, err := New(newMockWalletProvider(mockStoreProvider))
		require.NoError(t, err)

		didDoc, err := w.CreateDID(peerDIDMethod, didcreator.WithServiceType(serviceTypeDIDComm))
		require.Nil(t, didDoc)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to create DID")
		require.Contains(t, err.Error(), errMsg)

		didDoc, err = w.GetDID("sample-did")
		require.Nil(t, didDoc)
		require.NotNil(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
	})

	t.Run("invalid DID method", func(t *testing.T) {
		w, err := New(newMockWalletProvider(storeProvider))
		require.NoError(t, err)
		_, err = w.CreateDID("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid DID Method")
	})
}

func TestBaseWallet_DeriveKEK(t *testing.T) {
	pk32, sk32, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kp := cryptoutil.KeyPair{Pub: pk32[:], Priv: sk32[:]}
	kpm, err := json.Marshal(kp)
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
		require.EqualError(t, e, "failed from GetKey: "+cryptoutil.ErrKeyNotFound.Error())
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
		w2, e := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{"testkey": {0, 0, 1, 0, 0}},
				},
			}))
		require.NoError(t, e)
		_, e = w2.FindVerKey([]string{"not present", "testkey"})
		require.NotNil(t, e)
		require.Contains(t, e.Error(), "failed from GetKey: failed unmarshal to key struct")
	})

	t.Run("test candidate signing key is not present", func(t *testing.T) {
		_, err = w.FindVerKey([]string{"not present"})
		require.EqualError(t, err, cryptoutil.ErrKeyNotFound.Error())
	})
}

func TestSecretWallet_GetKey(t *testing.T) {
	t.Run("test error getting corrupted key data", func(t *testing.T) {
		errGet := fmt.Errorf("error reading store")
		w, err := New(newMockWalletProvider(
			&mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store: map[string][]byte{"testkey": {0, 0, 1, 0, 0}}, ErrGet: errGet,
				},
			}))
		require.NoError(t, err)

		kp, err := w.GetKey("testkey")
		require.Equal(t, (*cryptoutil.KeyPair)(nil), kp)
		require.EqualError(t, err, errGet.Error())
	})
}
func TestSecretWallet_PutKey(t *testing.T) {
	t.Run("test error from persistKey", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte), ErrPut: fmt.Errorf("put error"),
		}}))
		require.NoError(t, err)

		kp := cryptoutil.KeyPair{
			Priv: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			Pub:  []byte{0, 1, 0, 1, 0, 1, 0, 1, 0},
		}

		err = w.PutKey("pub", &kp)
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})
}

type mockCryptoOp struct {
	ret error
	kh  operator.KeyHolder
}

func (m *mockCryptoOp) InjectKeyHolder(kh operator.KeyHolder) error {
	m.kh = kh
	return m.ret
}

func TestSecretWallet_AttachCryptoOperator(t *testing.T) {
	t.Run("test attaching crypto op", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		m := mockCryptoOp{
			ret: nil,
			kh:  nil,
		}

		err = w.AttachCryptoOperator(&m)
		require.NoError(t, err)
		require.Equal(t, w, m.kh)

		m2 := mockCryptoOp{
			ret: fmt.Errorf("test error"),
			kh:  nil,
		}
		err = w.AttachCryptoOperator(&m2)
		require.EqualError(t, err, "test error")
	})

	t.Run("test attaching nil crypto op", func(t *testing.T) {
		w, err := New(newMockWalletProvider(&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{
			Store: make(map[string][]byte),
		}}))
		require.NoError(t, err)

		err = w.AttachCryptoOperator(nil)
		require.EqualError(t, err, "cannot attach nil crypto operator")
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

func (m *mockProvider) InboundTransportEndpoint() string {
	return serviceEndpoint
}
