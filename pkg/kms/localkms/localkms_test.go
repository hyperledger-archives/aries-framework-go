/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestNewKMS_Failure(t *testing.T) {
	// create a mock storage provider for NewKMS()
	leveldbStore := &mockstorage.MockStoreWithDelete{
		MockStore: mockstorage.MockStore{Store: map[string][]byte{}}}

	t.Run("test NewKMS() fail without masterkey in env", func(t *testing.T) {
		kmsStorage, err := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: leveldbStore,
		}})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})

	const testKeyURI = "local-lock://test/key/uri"

	// try to create a new KMS service with an empty keyURI
	t.Run("test NewKMS() fail with empty masterkey in env", func(t *testing.T) {
		// first set keyURI in an env variable (backup original env variable)
		currentKeyURI := os.Getenv(masterKeyLabel)

		envKey := "LOCAL_EmptyKeyURI"
		err := os.Setenv(envKey, "")
		require.NoError(t, err)

		// remove test masterKey from env once done testing
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		err = os.Setenv(masterKeyLabel, testKeyURI)
		require.NoError(t, err)

		// restore original env variable once done testing
		defer func() {
			e := os.Setenv(masterKeyLabel, currentKeyURI)
			require.NoError(t, e)
		}()

		kmsStorage, err := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: nil,
		}})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})

	t.Run("test NewKMS() fail due to error opening store", func(t *testing.T) {
		currentKeyURI := os.Getenv(masterKeyLabel)
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")

		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)

		// remove test masterKey from env once done testing
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		err = os.Setenv(masterKeyLabel, testKeyURI)
		require.NoError(t, err)

		// restore original env variable once done testing
		defer func() {
			e := os.Setenv(masterKeyLabel, currentKeyURI)
			require.NoError(t, e)
		}()

		kmsStorage, err := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("failed to create store"),
		}})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})

	t.Run("test NewKMS() error creating new KMS client with bad master key prefix", func(t *testing.T) {
		currentKeyURI := os.Getenv(masterKeyLabel)
		masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
		masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
		batTKeyURI := "bad-prefix://test/key/uri"
		envKey := "LOCAL_" + strings.ReplaceAll(batTKeyURI, "/", "_")
		err := os.Setenv(envKey, masterKeyEnc)
		require.NoError(t, err)

		// remove test masterKey from env once done testing
		defer func() {
			e := os.Unsetenv(envKey)
			require.NoError(t, e)
		}()

		err = os.Setenv(masterKeyLabel, batTKeyURI)
		require.NoError(t, err)

		// restore original env variable once done testing
		defer func() {
			e := os.Setenv(masterKeyLabel, currentKeyURI)
			require.NoError(t, e)
		}()

		leveldbStore := &mockstorage.MockStoreWithDelete{
			MockStore: mockstorage.MockStore{Store: map[string][]byte{}}}

		kmsStorage, err := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: leveldbStore,
		}})
		require.Error(t, err)
		require.Empty(t, kmsStorage)
	})
}

func TestCreateGetRoteKey_Failure(t *testing.T) {
	const testKeyURI = "local-lock://test/key/uri"

	currentKeyURI := os.Getenv(masterKeyLabel)
	masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
	masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)

	envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
	err := os.Setenv(envKey, masterKeyEnc)
	require.NoError(t, err)

	// remove test masterKey from env once done testing
	defer func() {
		e := os.Unsetenv(envKey)
		require.NoError(t, e)
	}()

	err = os.Setenv(masterKeyLabel, testKeyURI)
	require.NoError(t, err)

	// restore original env variable once done testing
	defer func() {
		e := os.Setenv(masterKeyLabel, currentKeyURI)
		require.NoError(t, e)
	}()

	// create a mock storage provider for NewKMS()
	leveldbStore := &mockstorage.MockStoreWithDelete{
		MockStore: mockstorage.MockStore{Store: map[string][]byte{}}}

	t.Run("test failure Create() and Rotate() calls with bad key template string", func(t *testing.T) {
		kmsStorage, er := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: leveldbStore,
		}})
		require.NoError(t, er)
		require.NotEmpty(t, kmsStorage)

		id, kh, er := kmsStorage.Create("")
		require.Error(t, er)
		require.Empty(t, kh)
		require.Empty(t, id)

		id, kh, er = kmsStorage.Create("unsupported")
		require.Error(t, er)
		require.Empty(t, kh)
		require.Empty(t, id)

		// create a valid key to test Rotate()
		id, kh, er = kmsStorage.Create("AES128GCM")
		require.NoError(t, er)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		newID, kh, er := kmsStorage.Rotate("", id)
		require.Error(t, er)
		require.Empty(t, kh)
		require.Empty(t, newID)

		newID, kh, er = kmsStorage.Rotate("unsupported", id)
		require.Error(t, er)
		require.Empty(t, kh)
		require.Empty(t, newID)
	})

	t.Run("test Create() with failure to store key", func(t *testing.T) {
		kmsStorage, er := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: &mockstorage.MockStoreWithDelete{
				MockStore: mockstorage.MockStore{ErrPut: fmt.Errorf("failed to put data")},
			}}})
		require.NoError(t, er)

		id, kh, er := kmsStorage.Create("AES128GCM")
		require.EqualError(t, er, "failed to put data")
		require.Empty(t, kh)
		require.Empty(t, id)
	})

	t.Run("test Create() success to store key but fail to get key from store", func(t *testing.T) {
		storeData := map[string][]byte{}
		kmsStorage, er := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: &mockstorage.MockStoreWithDelete{
				MockStore: mockstorage.MockStore{
					Store: storeData,
				},
			}}})
		require.NoError(t, er)

		id, kh, er := kmsStorage.Create("AES128GCM")
		require.NoError(t, er)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		// new create a new client with a store throwing an error during a Get()
		kmsStorage3, er := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
			StoreWithDelete: &mockstorage.MockStoreWithDelete{
				MockStore: mockstorage.MockStore{
					ErrGet: fmt.Errorf("failed to get data"),
					Store:  storeData,
				},
			}}})
		require.NoError(t, er)

		kh, er = kmsStorage3.Get(id)
		require.EqualError(t, er, "failed to get data")
		require.Empty(t, kh)

		newID, kh, er := kmsStorage3.Rotate("AES128GCM", id)
		require.EqualError(t, er, "failed to get data")
		require.Empty(t, kh)
		require.Empty(t, newID)
	})
}

func TestLocalKMS_Success(t *testing.T) {
	const testKeyURI = "local-lock://test/key/uri"

	// verify LocalKMS implements kms.KeyManager
	require.Implements(t, (*kms.KeyManager)(nil), (*LocalKMS)(nil))

	// first set keyURI in an env variable (backup original env variable)
	currentKeyURI := os.Getenv(masterKeyLabel)

	err := os.Setenv(masterKeyLabel, testKeyURI)
	require.NoError(t, err)

	// restore original env variable once done testing
	defer func() {
		e := os.Setenv(masterKeyLabel, currentKeyURI)
		require.NoError(t, e)
	}()

	// second create a new test masterKey and set it in an env variable
	masterKey := random.GetRandomBytes(chacha20poly1305.KeySize)
	masterKeyEnc := base64.URLEncoding.EncodeToString(masterKey)
	envKey := "LOCAL_" + strings.ReplaceAll(testKeyURI, "/", "_")
	err = os.Setenv(envKey, masterKeyEnc)
	require.NoError(t, err)

	// remove test masterKey from env once done testing
	defer func() {
		e := os.Unsetenv(envKey)
		require.NoError(t, e)
	}()

	// create a mock storage provider for NewKMS()
	leveldbStore := &mockstorage.MockStoreWithDelete{
		MockStore: mockstorage.MockStore{Store: map[string][]byte{}}}

	// test NewKMS()
	kmsStorage, err := NewKMS(&mockProvider{&mockstorage.MockStoreProvider{
		StoreWithDelete: leveldbStore,
	}})
	require.NoError(t, err)
	require.NotEmpty(t, kmsStorage)

	keyTemplates := []string{
		"AES128GCM",
		"AES256GCMNoPrefix",
		"AES256GCM",
		"ChaCha20Poly1305",
		"XChaCha20Poly1305",
		"ECDSAP256",
		"ECDSAP384",
		"ECDSAP521",
		"ED25519",
	}

	for _, v := range keyTemplates {
		// test Create() a new key
		keyID, newKeyHandle, er := kmsStorage.Create(v)
		require.NoError(t, er)
		require.NotEmpty(t, newKeyHandle)
		require.NotEmpty(t, keyID)

		newKHPrimitives, er := newKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, er)
		require.NotEmpty(t, newKHPrimitives)

		// test Get() an existing keyhandle (it should match newKeyHandle above)
		loadedKeyHandle, er := kmsStorage.Get(keyID)
		require.NoError(t, er)
		require.NotEmpty(t, loadedKeyHandle)

		readKHPrimitives, er := loadedKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, er)
		require.NotEmpty(t, newKHPrimitives)

		require.Equal(t, len(newKHPrimitives.Entries), len(readKHPrimitives.Entries))

		// finally test Rotate()
		newKeyID, rotatedKeyHandle, er := kmsStorage.Rotate(v, keyID)
		require.NoError(t, er)
		require.NotEmpty(t, rotatedKeyHandle)
		require.NotEqual(t, newKeyID, keyID)

		rotatedKHPrimitives, er := loadedKeyHandle.(*keyset.Handle).Primitives()
		require.NoError(t, er)
		require.NotEmpty(t, newKHPrimitives)
		require.Equal(t, len(newKHPrimitives.Entries), len(rotatedKHPrimitives.Entries))
		require.Equal(t, len(readKHPrimitives.Entries), len(rotatedKHPrimitives.Entries))
	}
}

// mockProvider mocks provider for KMS storage
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}
