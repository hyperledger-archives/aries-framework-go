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
	"net/http/httptest"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	testKey = "key"

	vaultIDPathVariable    = "vaultID"
	docIDPathVariable      = "docID"
	queryVaultEndpoint     = "/{" + vaultIDPathVariable + "}/query"
	createDocumentEndpoint = "/{" + vaultIDPathVariable + "}/documents"
	readDocumentEndpoint   = "/{" + vaultIDPathVariable + "}/documents/{" + docIDPathVariable + "}"
)

var errTest = errors.New("test error")

func TestNewRESTProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		createRESTProvider(t, "EDVServerURL")
	})
	t.Run("Fail to compute index name MAC", func(t *testing.T) {
		provider, err := NewRESTProvider("EDVServerURL", "vaultID",
			NewMACCrypto(nil, &mockcrypto.Crypto{ComputeMACErr: errTest}))
		require.EqualError(t, err, fmt.Errorf(failComputeMACIndexName, errTest).Error())
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
		mockSDSServerOperation := mockSDSServerOperation{
			createDocumentReturnLocation:   "documentLocation",
			createDocumentReturnStatusCode: http.StatusCreated,
		}
		sdsSrv := mockSDSServerOperation.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocument := EncryptedDocument{}

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

		encryptedDocument := EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		err = store.Put(testKey, encryptedDocumentBytes)
		require.EqualError(t, err,
			fmt.Errorf(failCreateIndexedAttribute,
				fmt.Errorf(failComputeBase64EncodedIndexValueMAC,
					fmt.Errorf(failComputeMACIndexValue, errTest))).Error())
	})
	t.Run("Receive error response from EDV server", func(t *testing.T) {
		mockSDSServerOp := mockSDSServerOperation{
			createDocumentReturnStatusCode: http.StatusInternalServerError,
			createDocumentReturnBody:       []byte(errTest.Error()),
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		encryptedDocument := EncryptedDocument{}

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
		encryptedDocument := EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		queryResults := []string{"https://example.com/encrypted-data-vaults/z4sRgBJJLnYy/docs/zMbxmSDn2Xzz"}

		queryResultsBytes, err := json.Marshal(queryResults)
		require.NoError(t, err)

		mockSDSServerOp := mockSDSServerOperation{
			queryVaultReturnStatusCode:   http.StatusOK,
			queryVaultReturnBody:         queryResultsBytes,
			readDocumentReturnStatusCode: http.StatusOK,
			readDocumentReturnBody:       encryptedDocumentBytes,
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

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
			fmt.Errorf(failComputeBase64EncodedIndexValueMAC,
				fmt.Errorf(failComputeMACIndexValue, errTest)).Error())
		require.Nil(t, encryptedDocumentBytes)
	})
	t.Run("Receive error response from EDV server query endpoint", func(t *testing.T) {
		mockSDSServerOp := mockSDSServerOperation{
			queryVaultReturnStatusCode: http.StatusInternalServerError,
			queryVaultReturnBody:       []byte(errTest.Error()),
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

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

		mockSDSServerOp := mockSDSServerOperation{
			queryVaultReturnStatusCode: http.StatusOK,
			queryVaultReturnBody:       queryResultsBytes,
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

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

		mockSDSServerOp := mockSDSServerOperation{
			queryVaultReturnStatusCode: http.StatusOK,
			queryVaultReturnBody:       queryResultsBytes,
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

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

		mockSDSServerOp := mockSDSServerOperation{
			queryVaultReturnStatusCode:   http.StatusOK,
			queryVaultReturnBody:         queryResultsBytes,
			readDocumentReturnStatusCode: http.StatusInternalServerError,
			readDocumentReturnBody:       []byte(errTest.Error()),
		}
		sdsSrv := mockSDSServerOp.startNewMockSDSServer()
		defer sdsSrv.Close()

		provider := createRESTProvider(t, sdsSrv.URL)

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
	provider := createRESTProvider(t, "EDVServerURL")

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)
	require.NotNil(t, store)

	iterator := store.Iterator("StartKey", "EndKey")
	require.False(t, iterator.Next())
	require.Nil(t, iterator.Key())
	require.Nil(t, iterator.Value())
	require.Equal(t, errIteratorNotSupported, iterator.Error())
	iterator.Release()
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

type mockSDSServerOperation struct {
	createDocumentReturnStatusCode int
	createDocumentReturnLocation   string
	createDocumentReturnBody       []byte
	readDocumentReturnStatusCode   int
	readDocumentReturnBody         []byte
	queryVaultReturnStatusCode     int
	queryVaultReturnBody           []byte
}

func (o *mockSDSServerOperation) startNewMockSDSServer() *httptest.Server {
	router := mux.NewRouter()
	router.UseEncodedPath()

	router.HandleFunc(createDocumentEndpoint, o.mockCreateDocumentHandler).Methods(http.MethodPost)
	router.HandleFunc(readDocumentEndpoint, o.mockReadDocumentHandler).Methods(http.MethodGet)
	router.HandleFunc(queryVaultEndpoint, o.mockQueryVaultHandler).Methods(http.MethodPost)

	return httptest.NewServer(router)
}

func (o *mockSDSServerOperation) mockCreateDocumentHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Location", o.createDocumentReturnLocation)
	rw.WriteHeader(o.createDocumentReturnStatusCode)

	_, err := rw.Write(o.createDocumentReturnBody)
	if err != nil {
		logger.Errorf("failed to write return body: %w", err)
	}
}

func (o *mockSDSServerOperation) mockReadDocumentHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(o.readDocumentReturnStatusCode)

	_, err := rw.Write(o.readDocumentReturnBody)
	if err != nil {
		logger.Errorf("failed to write return body: %w", err)
	}
}

func (o *mockSDSServerOperation) mockQueryVaultHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(o.queryVaultReturnStatusCode)

	_, err := rw.Write(o.queryVaultReturnBody)
	if err != nil {
		logger.Errorf("failed to write return body: %w", err)
	}
}
