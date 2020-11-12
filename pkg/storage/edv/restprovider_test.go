/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/mock/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

var errTest = errors.New("test error")

func TestNewRESTProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		createRESTProvider(t, "EDVServerURL")
	})
	t.Run("Fail to compute index name MAC", func(t *testing.T) {
		provider, err := NewRESTProvider("EDVServerURL", "vaultID",
			NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest}))
		require.EqualError(t, err, fmt.Errorf(failComputeMACStoreAndKeyIndexName, errTest).Error())
		require.Nil(t, provider)
	})
}

func TestRESTProvider_OpenStore(t *testing.T) {
	provider := createRESTProvider(t, "EDVServerURL")

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestRESTProvider_CloseStore(t *testing.T) {
	provider := createRESTProvider(t, "EDVServerURL")

	err := provider.CloseStore("StoreName")
	require.NoError(t, err)
}

func TestRESTProvider_Close(t *testing.T) {
	provider := createRESTProvider(t, "EDVServerURL")

	err := provider.Close()
	require.NoError(t, err)
}

func TestRestStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockEDVServerOperation := edv.MockServerOperation{
			T:                              t,
			CreateDocumentReturnLocation:   "documentLocation",
			CreateDocumentReturnStatusCode: http.StatusCreated,
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocument := models.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		err = store.Put(testKey, encryptedDocumentBytes)
		require.NoError(t, err)
	})
	t.Run("Fail to unmarshal value into an encrypted document", func(t *testing.T) {
		provider := createRESTProvider(t, "EDVServerURL")

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put(testKey, []byte("this can't be unmarshalled to an EncryptedDocument"))
		require.EqualError(t, err, fmt.Errorf(failUnmarshalValueIntoEncryptedDocument,
			errors.New("invalid character 'h' in literal true (expecting 'r')")).Error())
	})
	t.Run("Fail to create indexed attribute", func(t *testing.T) {
		provider := createRESTProvider(t, "EDVServerURL")
		provider.macCrypto = NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest})

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocument := models.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		err = store.Put(testKey, encryptedDocumentBytes)
		require.EqualError(t, err,
			fmt.Errorf(failCreateIndexedAttribute,
				fmt.Errorf(failComputeMACStoreIndexValue, errTest)).Error())
	})
	t.Run("Receive error response from EDV server", func(t *testing.T) {
		mockEDVServerOperation := edv.MockServerOperation{
			T:                              t,
			CreateDocumentReturnStatusCode: http.StatusInternalServerError,
			CreateDocumentReturnBody:       []byte(errTest.Error()),
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocument := models.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		err = store.Put(testKey, encryptedDocumentBytes)
		require.EqualError(t, err,
			fmt.Errorf(failCreateDocumentInEDVServer,
				fmt.Errorf(failResponseFromEDVServer, http.StatusInternalServerError, errTest.Error())).Error())
	})
}

func TestRestStore_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		encryptedDocument := models.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		queryResults := []string{"https://example.com/encrypted-data-vaults/z4sRgBJJLnYy/docs/zMbxmSDn2Xzz"}

		queryResultsBytes, err := json.Marshal(queryResults)
		require.NoError(t, err)

		mockEDVServerOp := edv.MockServerOperation{
			T:                            t,
			QueryVaultReturnStatusCode:   http.StatusOK,
			QueryVaultReturnBody:         queryResultsBytes,
			ReadDocumentReturnStatusCode: http.StatusOK,
			ReadDocumentReturnBody:       encryptedDocumentBytes,
		}
		edvSrv := mockEDVServerOp.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytesFromServer, err := store.Get(testKey)
		require.NoError(t, err)
		require.Equal(t, string(encryptedDocumentBytes), string(encryptedDocumentBytesFromServer))
	})
	t.Run("Fail to compute Base64 encoded index value MAC", func(t *testing.T) {
		provider := createRESTProvider(t, "EDVServerURL")
		provider.macCrypto = NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest})

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytes, err := store.Get(testKey)
		require.EqualError(t, err,
			fmt.Errorf(failComputeBase64EncodedStoreAndKeyIndexValueMAC,
				fmt.Errorf(failComputeMACStoreAndKeyIndexValue, errTest)).Error())
		require.Nil(t, encryptedDocumentBytes)
	})
	t.Run("Receive error response from EDV server query endpoint", func(t *testing.T) {
		mockEDVServerOperation := edv.MockServerOperation{
			T:                          t,
			QueryVaultReturnStatusCode: http.StatusInternalServerError,
			QueryVaultReturnBody:       []byte(errTest.Error()),
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytes, err := store.Get(testKey)
		require.EqualError(t, err,
			fmt.Errorf(failQueryVaultInEDVServer,
				fmt.Errorf(failResponseFromEDVServer, http.StatusInternalServerError, errTest.Error())).Error())
		require.Nil(t, encryptedDocumentBytes)
	})
	t.Run("No document was found matching the query", func(t *testing.T) {
		queryResults := make([]string, 0)

		queryResultsBytes, err := json.Marshal(queryResults)
		require.NoError(t, err)

		mockEDVServerOperation := edv.MockServerOperation{
			T:                          t,
			QueryVaultReturnStatusCode: http.StatusOK,
			QueryVaultReturnBody:       queryResultsBytes,
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytes, err := store.Get(testKey)
		require.EqualError(t, err, fmt.Errorf(noDocumentMatchingQueryFound, storage.ErrDataNotFound).Error())
		require.Nil(t, encryptedDocumentBytes)
	})
	t.Run("Multiple documents found matching the query", func(t *testing.T) {
		queryResults := []string{
			"https://example.com/encrypted-data-vaults/z4sRgBJJLnYy/docs/zMbxmSDn2Xzz",
			"https://example.com/encrypted-data-vaults/z4sRgBJJLnYy/docs/AJYHHJx4C8J9Fsgz7rZqSp",
		}

		queryResultsBytes, err := json.Marshal(queryResults)
		require.NoError(t, err)

		mockEDVServerOperation := edv.MockServerOperation{
			T:                          t,
			QueryVaultReturnStatusCode: http.StatusOK,
			QueryVaultReturnBody:       queryResultsBytes,
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytes, err := store.Get(testKey)
		require.EqualError(t, err, errMultipleDocumentsMatchingQuery.Error())
		require.Nil(t, encryptedDocumentBytes)
	})
	t.Run("Receive error response from EDV server read document endpoint", func(t *testing.T) {
		queryResults := []string{"z19x9iFMnfo4YLsShKAvnJk4L"}

		queryResultsBytes, err := json.Marshal(queryResults)
		require.NoError(t, err)

		mockEDVServerOperation := edv.MockServerOperation{
			T:                            t,
			QueryVaultReturnStatusCode:   http.StatusOK,
			QueryVaultReturnBody:         queryResultsBytes,
			ReadDocumentReturnStatusCode: http.StatusInternalServerError,
			ReadDocumentReturnBody:       []byte(errTest.Error()),
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocumentBytesFromServer, err := store.Get(testKey)
		require.EqualError(t, err,
			fmt.Errorf(failRetrieveDocumentFromEDVServer,
				fmt.Errorf(failResponseFromEDVServer, http.StatusInternalServerError, errTest.Error())).Error())
		require.Nil(t, encryptedDocumentBytesFromServer)
	})
}

func TestRestStore_Iterator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockEDVServerOperation := edv.MockServerOperation{
			T:                              t,
			DB:                             make(map[string][]byte),
			UseDB:                          true,
			CreateDocumentReturnStatusCode: http.StatusCreated,
			ReadDocumentReturnStatusCode:   http.StatusOK,
			QueryVaultReturnStatusCode:     http.StatusOK,
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		const valPrefix = "val-for-%s"
		keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}
		encryptedFormatter := createEncryptedFormatter(t)

		for _, key := range keys {
			encryptedDocument, err := encryptedFormatter.FormatPair(key, []byte(fmt.Sprintf(valPrefix, key)))
			require.NoError(t, err)

			err = store.Put(key, encryptedDocument)
			require.NoError(t, err)
		}

		iterator := store.Iterator("Start key doesn't matter", "End key doesn't matter")
		verifyIterator(t, iterator, len(keys))
	})
	t.Run("Fail to get all document locations", func(t *testing.T) {
		provider := createRESTProvider(t, "EDVServerURL")

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		itr := store.Iterator("Start key doesn't matter", "End key doesn't matter")
		require.EqualError(t, itr.Error(),
			fmt.Errorf(failGetAllDocumentLocations,
				fmt.Errorf(failQueryVaultInEDVServer,
					errors.New(`failed to send POST request: Post "EDVServerURL/vaultID/query": `+
						`unsupported protocol scheme ""`))).Error())
	})
	t.Run("Fail to get all original key document pairs", func(t *testing.T) {
		mockEDVServerOperation := edv.MockServerOperation{
			T:                              t,
			DB:                             make(map[string][]byte),
			UseDB:                          true,
			CreateDocumentReturnStatusCode: http.StatusCreated,
			ReadDocumentReturnStatusCode:   http.StatusInternalServerError,
			ReadDocumentReturnBody:         []byte(errTest.Error()),
			QueryVaultReturnStatusCode:     http.StatusOK,
		}
		edvSrv := mockEDVServerOperation.StartNewMockEDVServer()
		defer edvSrv.Close()

		provider := createRESTProvider(t, edvSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		const valPrefix = "val-for-%s"
		keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}
		encryptedFormatter := createEncryptedFormatter(t)

		for _, key := range keys {
			encryptedDocument, err := encryptedFormatter.FormatPair(key, []byte(fmt.Sprintf(valPrefix, key)))
			require.NoError(t, err)

			err = store.Put(key, encryptedDocument)
			require.NoError(t, err)
		}

		itr := store.Iterator("Start key doesn't matter", "End key doesn't matter")
		require.EqualError(t, itr.Error(),
			fmt.Errorf(failGetAllDocuments,
				fmt.Errorf(failRetrieveDocumentFromEDVServer,
					fmt.Errorf(failResponseFromEDVServer, http.StatusInternalServerError, errTest.Error()))).Error())
	})
}

func TestRestStore_Delete(t *testing.T) {
	provider := createRESTProvider(t, "EDVServerURL")

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)
	require.NotNil(t, store)

	err = store.Delete(testKey)
	require.Equal(t, errDeleteNotSupported, err)
}

func createRESTProvider(t *testing.T, edvServerURL string) *RESTProvider {
	provider, err := NewRESTProvider(edvServerURL, "vaultID", newMACCrypto(t),
		WithTLSConfig(&tls.Config{ServerName: "name", MinVersion: tls.VersionTLS13}))
	require.NoError(t, err)
	require.NotNil(t, provider)

	return provider
}

func newMACCrypto(t *testing.T) *MACCrypto {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	return NewMACCrypto(kh, crypto)
}

func verifyIterator(t *testing.T, itr storage.StoreIterator, count int) {
	t.Helper()

	var values []string

	for itr.Next() {
		require.NotEmpty(t, itr.Key())

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
