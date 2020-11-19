/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockedv "github.com/hyperledger/aries-framework-go/pkg/mock/edv"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/formattedstore"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

const (
	testKey   = "key"
	testValue = "data"
)

var errTest = errors.New("test error")

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
		require.NotNil(t, provider)
	})
}

func TestFormatProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.MockStoreProvider{ErrOpenStoreHandle: errTest}

		provider := formattedstore.NewFormattedProvider(&mockStoreProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.EqualError(t, err, fmt.Errorf("failed to open underlying store: %w", errTest).Error())
		require.Nil(t, store)
	})
}

func TestFormatProvider_CloseStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
		require.NotNil(t, provider)

		err := provider.CloseStore("testName")
		require.NoError(t, err)
	})
	t.Run("Fail to close store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrCloseStore = errTest

		provider := formattedstore.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		err := provider.CloseStore("testName")
		require.EqualError(t, err, fmt.Errorf("failed to close underlying store: %w", errTest).Error())
	})
}

func TestFormatProvider_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
		require.NotNil(t, provider)

		err := provider.Close()
		require.NoError(t, err)
	})
	t.Run("Fail to close all stores in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrClose = errTest

		provider := formattedstore.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, fmt.Errorf("failed to close all underlying stores: %w", errTest).Error())
	})
}

func Test_formatStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte(testValue))
		require.NoError(t, err)
	})
	t.Run("Fail to format value", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), &failingFormatter{}, true)
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

		provider := formattedstore.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t), true)
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
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
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

		provider := formattedstore.NewFormattedProvider(underlyingProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get(testKey)
		require.EqualError(t, err,
			"failed to parse formatted value: failed to get structured document from "+
				"encrypted document bytes: failed to unmarshal value into an encrypted document: "+
				"invalid character 'o' in literal null (expecting 'u')")
		require.Nil(t, value)
	})
	t.Run("Fail to get formatted value from underlying store", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
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
	t.Run("Success with in-memory provider as the underlying provider", func(t *testing.T) {
		t.Run("skipIteratorFiltering set to false", func(t *testing.T) {
			provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), false)
			require.NotNil(t, provider)

			store, err := provider.OpenStore("testName")
			require.NoError(t, err)
			require.NotNil(t, store)

			const valPrefix = "val-for-%s"
			keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

			for _, key := range keys {
				err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
				require.NoError(t, err)
			}

			// Since the underlying mem store already did the range filtering, it's expected that the filter done by
			// the upper layer FormatProvider is completely redundant. It should effectively pass the underlying iterator
			// through.
			itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("abc_", "abc_")
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("", "")
			verifyIterator(t, itr, 0, "")

			itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_123")
			verifyIterator(t, itr, 6, "")

			itr = store.Iterator("t_", "t_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 0, "")
		})
		t.Run("skipIteratorFiltering set to true", func(t *testing.T) {
			provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
			require.NotNil(t, provider)

			store, err := provider.OpenStore("testName")
			require.NoError(t, err)
			require.NotNil(t, store)

			const valPrefix = "val-for-%s"
			keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

			for _, key := range keys {
				err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
				require.NoError(t, err)
			}

			itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("abc_", "abc_")
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("", "")
			verifyIterator(t, itr, 0, "")

			itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_123")
			verifyIterator(t, itr, 6, "")

			itr = store.Iterator("t_", "t_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 0, "")
		})
	})
	t.Run("Success with EDV REST provider as the underlying provider", func(t *testing.T) {
		t.Run("skipIteratorFiltering set to false", func(t *testing.T) {
			queryResults := make([]string, 0)

			queryResultsBytes, err := json.Marshal(queryResults)
			require.NoError(t, err)

			mockEDVServerOp := mockedv.MockServerOperation{
				T:                              t,
				DB:                             make(map[string][]byte),
				UseDB:                          true,
				CreateDocumentReturnStatusCode: http.StatusCreated,
				ReadDocumentReturnStatusCode:   http.StatusOK,
				QueryVaultReturnStatusCode:     http.StatusOK,
				QueryVaultReturnBody:           queryResultsBytes,
			}
			edvSrv := mockEDVServerOp.StartNewMockEDVServer()
			defer edvSrv.Close()

			underlyingProvider := createEDVRESTProvider(t, edvSrv.URL)

			provider := formattedstore.NewFormattedProvider(underlyingProvider, createEDVFormatter(t), false)
			require.NotNil(t, provider)

			store, err := provider.OpenStore("testName")
			require.NoError(t, err)
			require.NotNil(t, store)

			const valPrefix = "val-for-%s"
			keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

			for _, key := range keys {
				err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
				require.NoError(t, err)
			}

			// Allow the mock EDV server to return all documents in query
			mockEDVServerOp.QueryVaultReturnBody = nil

			// The underlying EDV REST provider's Iterator(startKey, endKey string) method does not do any filtering
			// based on the startKey and endKey arguments. It always contains every document in the store.
			// We rely on the FormatProvider's filter to do this.
			itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("abc_", "abc_")
			verifyIterator(t, itr, 4, "abc_")

			itr = store.Iterator("", "")
			verifyIterator(t, itr, 0, "")

			itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_123")
			verifyIterator(t, itr, 6, "")

			itr = store.Iterator("t_", "t_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 0, "")
		})
		t.Run("skipIteratorFiltering set to true", func(t *testing.T) {
			queryResults := make([]string, 0)

			queryResultsBytes, err := json.Marshal(queryResults)
			require.NoError(t, err)

			mockEDVServerOp := mockedv.MockServerOperation{
				T:                              t,
				DB:                             make(map[string][]byte),
				UseDB:                          true,
				CreateDocumentReturnStatusCode: http.StatusCreated,
				ReadDocumentReturnStatusCode:   http.StatusOK,
				QueryVaultReturnStatusCode:     http.StatusOK,
				QueryVaultReturnBody:           queryResultsBytes,
			}
			edvSrv := mockEDVServerOp.StartNewMockEDVServer()
			defer edvSrv.Close()

			underlyingProvider := createEDVRESTProvider(t, edvSrv.URL)

			provider := formattedstore.NewFormattedProvider(underlyingProvider, createEDVFormatter(t), true)
			require.NotNil(t, provider)

			store, err := provider.OpenStore("testName")
			require.NoError(t, err)
			require.NotNil(t, store)

			const valPrefix = "val-for-%s"
			keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

			for _, key := range keys {
				err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
				require.NoError(t, err)
			}

			// Allow the mock EDV server to return all documents in query
			mockEDVServerOp.QueryVaultReturnBody = nil

			// The underlying EDV REST provider's Iterator(startKey, endKey string) method does not do any filtering
			// based on the startKey and endKey arguments. The iterator is returns always contains every document
			// in the store. Since skipIteratorFiltering in the FormatProvider is enabled, no filtering gets done
			// and so regardless of the startKey and endKey passed in, FormatProvider's
			// Iterator(startKey, endKey string) method also returns an iterator that contains all values.
			itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "abc_")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("", "")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_123")
			verifyIterator(t, itr, 7, "")

			itr = store.Iterator("t_", "t_"+storage.EndKeySuffix)
			verifyIterator(t, itr, 7, "")
		})
	})
	t.Run("Fail to get iterator from the underlying store", func(t *testing.T) {
		mockProvider := mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
			ErrItr: errTest,
		})
		provider := formattedstore.NewFormattedProvider(mockProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		itr := store.Iterator("", "")
		require.EqualError(t, itr.Error(),
			fmt.Errorf("failed to get iterator from underlying store: %w", errTest).Error())
	})
	t.Run("Fail to parse value", func(t *testing.T) {
		underlyingProvider := mem.NewProvider()

		underlyingStore, err := underlyingProvider.OpenStore("testName")
		require.NoError(t, err)

		err = underlyingStore.Put(testKey, []byte(testValue))
		require.NoError(t, err)

		provider := formattedstore.NewFormattedProvider(underlyingProvider, &failingFormatter{}, true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		itr := store.Iterator(testKey, testKey+storage.EndKeySuffix)
		require.EqualError(t, itr.Error(),
			fmt.Errorf("failed to parse formatted value: %w", errFailingFormatter).Error())
	})
}

func Test_formatStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := formattedstore.NewFormattedProvider(mem.NewProvider(), createEDVFormatter(t), true)
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

		provider := formattedstore.NewFormattedProvider(mockStoreProvider, createEDVFormatter(t), true)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete(testKey)
		require.EqualError(t, err,
			fmt.Errorf("failed to delete key-value pair in underlying store: %w", errTest).Error())
	})
}

func createEDVFormatter(t *testing.T) formattedstore.Formatter {
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

func createEDVRESTProvider(t *testing.T, edvServerURL string) *edv.RESTProvider {
	provider, err := edv.NewRESTProvider(edvServerURL, "vaultID", newMACCrypto(t),
		edv.WithTLSConfig(&tls.Config{ServerName: "name", MinVersion: tls.VersionTLS13}))
	require.NoError(t, err)
	require.NotNil(t, provider)

	return provider
}

func newMACCrypto(t *testing.T) *edv.MACCrypto {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	return edv.NewMACCrypto(kh, crypto)
}

func verifyIterator(t *testing.T, itr storage.StoreIterator, count int, prefix string) {
	t.Helper()

	var values []string

	for itr.Next() {
		if prefix != "" {
			require.True(t, strings.HasPrefix(string(itr.Key()), prefix))
		}

		values = append(values, string(itr.Value()))
	}
	require.Len(t, values, count)

	itr.Release()
	require.False(t, itr.Next())
	require.Empty(t, itr.Key())
	require.Empty(t, itr.Value())
	require.Error(t, itr.Error())
	require.Contains(t, itr.Error().Error(), "iterator released")
}

var errFailingFormatter = errors.New("failingFormatter always fails")

type failingFormatter struct {
}

func (f *failingFormatter) FormatPair(string, []byte) ([]byte, error) {
	return nil, errFailingFormatter
}

func (f *failingFormatter) ParsePair([]byte) (string, []byte, error) {
	return "", nil, errFailingFormatter
}
