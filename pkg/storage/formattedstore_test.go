/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	testKey   = "key"
	testValue = "data"
)

var errTest = errors.New("test error")

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)
	})
}

func TestFormatProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.MockStoreProvider{ErrOpenStoreHandle: errTest}

		provider := storage.NewFormattedProvider(&mockStoreProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.EqualError(t, err, fmt.Errorf("failed to open underlying store: %w", errTest).Error())
		require.Nil(t, store)
	})
}

func TestFormatProvider_CloseStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		err := provider.CloseStore("testName")
		require.NoError(t, err)
	})
	t.Run("Fail to close store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrCloseStore = errTest

		provider := storage.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		err := provider.CloseStore("testName")
		require.EqualError(t, err, fmt.Errorf("failed to close underlying store: %w", errTest).Error())
	})
}

func TestFormatProvider_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		err := provider.Close()
		require.NoError(t, err)
	})
	t.Run("Fail to close all stores in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrClose = errTest

		provider := storage.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, fmt.Errorf("failed to close all underlying stores: %w", errTest).Error())
	})
}

func Test_formatStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte(testValue))
		require.NoError(t, err)
	})
	t.Run("Fail to format value", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), &failingFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte(testValue))
		require.EqualError(t, err,
			fmt.Errorf("failed to format value: %w", errFailingFormatter).Error())
	})
	t.Run("Fail to put formatted value into underlying store", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		provider := storage.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte(testValue))
		require.EqualError(t, err,
			fmt.Errorf("failed to put encrypted document in underlying store: %w", errTest).Error())
	})
}

func Test_formatStore_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte(testValue))
		require.NoError(t, err)

		value, err := store.Get(testKey)
		require.NoError(t, err)
		require.Equal(t, testValue, string(value))
	})
	t.Run("Fail to parse formatted value from underlying store", func(t *testing.T) {
		underlyingProvider := mem.NewProvider()

		const testStoreName = "testStoreName"

		underlyingStore, err := underlyingProvider.OpenStore(testStoreName)
		require.NoError(t, err)

		err = underlyingStore.Put(testKey, []byte("not EDV encrypted document formatted data"))
		require.NoError(t, err)

		provider := storage.NewFormattedProvider(underlyingProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get(testKey)
		require.EqualError(t, err,
			`failed to parse formatted value: failed to unmarshal value into an encrypted document: `+
				`invalid character 'o' in literal null (expecting 'u')`)
		require.Nil(t, value)
	})
	t.Run("Fail to get formatted value from underlying store", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get(testKey)
		require.EqualError(t, err,
			fmt.Errorf("failed to get formatted value from underlying store: %w", storage.ErrDataNotFound).Error())
		require.Nil(t, value)
	})
}

func Test_formatStore_Iterator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator := store.Iterator("", "")
		require.NotNil(t, iterator)
	})
}

func Test_formatStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := storage.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete(testKey)
		require.NoError(t, err)
	})
	t.Run("Fail to delete underlying store", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrDelete = errTest

		provider := storage.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete(testKey)
		require.EqualError(t, err,
			fmt.Errorf("failed to delete key-value pair in underlying store: %w", errTest).Error())
	})
}

func createEDVFormatter(t *testing.T) storage.Formatter {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	formatter := edv.NewEncryptedFormatter(encrypter, decrypter)
	require.NotNil(t, formatter)

	return formatter
}

func createEncrypterAndDecrypter(t *testing.T) (*jose.JWEEncrypt, *jose.JWEDecrypt) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	keyHandle, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	kmsSvc := &mockkms.KeyManager{
		GetKeyValue: keyHandle,
	}

	pubKH, err := keyHandle.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "EDVEncryptedDocument", "", nil,
		[]*cryptoapi.PublicKey{ecPubKey}, cryptoSvc)
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

	return encrypter, decrypter
}

var errFailingFormatter = errors.New("failingFormatter always fails")

type failingFormatter struct {
}

func (f *failingFormatter) Format([]byte) ([]byte, error) {
	return nil, errFailingFormatter
}

func (f *failingFormatter) ParseValue([]byte) ([]byte, error) {
	return nil, errFailingFormatter
}
