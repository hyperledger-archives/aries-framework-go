/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

const (
	vaultIDPathVariable    = "vaultID"
	docIDPathVariable      = "docID"
	queryVaultEndpoint     = "/{" + vaultIDPathVariable + "}/query"
	createDocumentEndpoint = "/{" + vaultIDPathVariable + "}/documents"
	readDocumentEndpoint   = "/{" + vaultIDPathVariable + "}/documents/{" + docIDPathVariable + "}"
)

// MockServerOperation represents a mocked EDV server that is useful for testing.
type MockServerOperation struct {
	T                              *testing.T
	DB                             map[string][]byte
	UseDB                          bool
	CreateDocumentReturnStatusCode int
	CreateDocumentReturnLocation   string
	CreateDocumentReturnBody       []byte
	ReadDocumentReturnStatusCode   int
	ReadDocumentReturnBody         []byte
	QueryVaultReturnStatusCode     int
	QueryVaultReturnBody           []byte
}

// StartNewMockEDVServer starts the MockServerOperation.
func (o *MockServerOperation) StartNewMockEDVServer() *httptest.Server {
	router := mux.NewRouter()
	router.UseEncodedPath()

	router.HandleFunc(createDocumentEndpoint, o.mockCreateDocumentHandler).Methods(http.MethodPost)
	router.HandleFunc(readDocumentEndpoint, o.mockReadDocumentHandler).Methods(http.MethodGet)
	router.HandleFunc(queryVaultEndpoint, o.mockQueryVaultHandler).Methods(http.MethodPost)

	return httptest.NewServer(router)
}

func (o *MockServerOperation) mockCreateDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	if o.UseDB {
		requestBody, err := ioutil.ReadAll(req.Body)
		require.NoError(o.T, err)

		var incomingDocument models.EncryptedDocument

		err = json.Unmarshal(requestBody, &incomingDocument)
		require.NoError(o.T, err)

		o.DB[incomingDocument.ID] = requestBody

		rw.Header().Set("Location", "SomeURLPart/"+incomingDocument.ID)
		rw.WriteHeader(o.CreateDocumentReturnStatusCode)
	} else {
		rw.Header().Set("Location", o.CreateDocumentReturnLocation)
		rw.WriteHeader(o.CreateDocumentReturnStatusCode)
	}

	_, err := rw.Write(o.CreateDocumentReturnBody)
	require.NoError(o.T, err)
}

func (o *MockServerOperation) mockReadDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(o.ReadDocumentReturnStatusCode)

	if o.ReadDocumentReturnStatusCode == http.StatusOK && o.UseDB {
		docID, err := url.PathUnescape(mux.Vars(req)[docIDPathVariable])
		require.NoError(o.T, err)

		documentBytes := o.DB[docID]

		_, err = rw.Write(documentBytes)
		require.NoError(o.T, err)
	} else {
		_, err := rw.Write(o.ReadDocumentReturnBody)
		require.NoError(o.T, err)
	}
}

func (o *MockServerOperation) mockQueryVaultHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(o.QueryVaultReturnStatusCode)

	if o.UseDB {
		allDocumentLocations := make([]string, 0)

		for docID := range o.DB {
			allDocumentLocations = append(allDocumentLocations, "SomeURLPart/"+docID)
		}

		allDocumentLocationsBytes, err := json.Marshal(allDocumentLocations)
		require.NoError(o.T, err)

		_, err = rw.Write(allDocumentLocationsBytes)
		require.NoError(o.T, err)
	} else {
		_, err := rw.Write(o.QueryVaultReturnBody)
		require.NoError(o.T, err)
	}
}
