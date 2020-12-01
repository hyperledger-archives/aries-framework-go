/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

const (
	vaultIDPathVariable    = "vaultID"
	docIDPathVariable      = "docID"
	queryVaultEndpoint     = "/{" + vaultIDPathVariable + "}/query"
	batchEndpoint          = "/{" + vaultIDPathVariable + "}/batch"
	createDocumentEndpoint = "/{" + vaultIDPathVariable + "}/documents"
	readDocumentEndpoint   = "/{" + vaultIDPathVariable + "}/documents/{" + docIDPathVariable + "}"
	deleteDocumentEndpoint = readDocumentEndpoint
	updateDocumentEndpoint = readDocumentEndpoint
)

// MockServerOperation represents a mocked EDV server that is useful for testing.
type MockServerOperation struct {
	T                              *testing.T
	DB                             map[string][]byte
	UseDB                          bool
	CreateDocumentReturnStatusCode int
	CreateDocumentReturnLocation   string
	CreateDocumentReturnBody       []byte
	UpdateDocumentReturnStatusCode int
	UpdateDocumentReturnBody       []byte
	ReadDocumentReturnStatusCode   int
	ReadDocumentReturnBody         []byte
	QueryVaultReturnStatusCode     int
	QueryVaultReturnBody           []byte
	DeleteDocumentReturnStatusCode int
	DeleteDocumentReturnBody       []byte
}

// StartNewMockEDVServer starts the MockServerOperation.
func (o *MockServerOperation) StartNewMockEDVServer() *httptest.Server {
	router := mux.NewRouter()
	router.UseEncodedPath()

	router.HandleFunc(createDocumentEndpoint, o.mockCreateDocumentHandler).Methods(http.MethodPost)
	router.HandleFunc(readDocumentEndpoint, o.mockReadDocumentHandler).Methods(http.MethodGet)
	router.HandleFunc(queryVaultEndpoint, o.mockQueryVaultHandler).Methods(http.MethodPost)
	router.HandleFunc(batchEndpoint, o.mockBatchHandler).Methods(http.MethodPost)
	router.HandleFunc(deleteDocumentEndpoint, o.mockDeleteDocumentHandler).Methods(http.MethodDelete)
	router.HandleFunc(updateDocumentEndpoint, o.mockUpdateDocumentHandler).Methods(http.MethodPost)

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

// Always returns all the document IDs or full documents depending on the ReturnFullDocuments field in the query.
func (o *MockServerOperation) mockQueryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(o.QueryVaultReturnStatusCode)

	requestBody, err := ioutil.ReadAll(req.Body)
	require.NoError(o.T, err)

	var incomingQuery models.Query

	err = json.Unmarshal(requestBody, &incomingQuery)
	require.NoError(o.T, err)

	if o.UseDB && o.QueryVaultReturnStatusCode == http.StatusOK && o.QueryVaultReturnBody == nil {
		if incomingQuery.ReturnFullDocuments {
			var allDocuments []models.EncryptedDocument

			for _, documentBytes := range o.DB {
				var document models.EncryptedDocument

				err := json.Unmarshal(documentBytes, &document)
				require.NoError(o.T, err)

				allDocuments = append(allDocuments, document)
			}

			allDocumentsBytes, err := json.Marshal(allDocuments)
			require.NoError(o.T, err)

			_, err = rw.Write(allDocumentsBytes)
			require.NoError(o.T, err)
		} else {
			allDocumentLocations := make([]string, 0)

			for docID := range o.DB {
				allDocumentLocations = append(allDocumentLocations, "SomeURLPart/"+docID)
			}

			allDocumentLocationsBytes, err := json.Marshal(allDocumentLocations)
			require.NoError(o.T, err)

			_, err = rw.Write(allDocumentLocationsBytes)
			require.NoError(o.T, err)
		}
	} else {
		_, err := rw.Write(o.QueryVaultReturnBody)
		require.NoError(o.T, err)
	}
}

func (o *MockServerOperation) mockBatchHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	require.NoError(o.T, err)

	var incomingBatch models.Batch

	err = json.Unmarshal(requestBody, &incomingBatch)
	require.NoError(o.T, err)

	responses := make([]string, len(incomingBatch))

	statusCode := http.StatusOK

loopOverOperations:
	for i, vaultOperation := range incomingBatch {
		switch {
		case strings.EqualFold(vaultOperation.Operation, models.UpsertDocumentVaultOperation):
			encryptedDocumentBytes, errMarshal := json.Marshal(vaultOperation.EncryptedDocument)
			require.NoError(o.T, errMarshal)

			_, isUpdate := o.DB[vaultOperation.EncryptedDocument.ID]

			o.DB[vaultOperation.EncryptedDocument.ID] = encryptedDocumentBytes

			if !isUpdate {
				responses[i] = "mockServerBaseURL/" + vaultOperation.EncryptedDocument.ID
			}
		case strings.EqualFold(vaultOperation.Operation, models.DeleteDocumentVaultOperation):
			delete(o.DB, vaultOperation.DocumentID)
		default:
			errInvalidOperation := fmt.Errorf("%s is not a valid vault operation", vaultOperation.Operation)
			responses[i] = errInvalidOperation.Error()
			statusCode = http.StatusBadRequest

			break loopOverOperations
		}
	}

	rw.WriteHeader(statusCode)

	responsesBytes, err := json.Marshal(responses)
	require.NoError(o.T, err)

	_, err = rw.Write(responsesBytes)
	require.NoError(o.T, err)
}

func (o *MockServerOperation) mockDeleteDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(o.DeleteDocumentReturnStatusCode)

	if o.DeleteDocumentReturnStatusCode == http.StatusOK && o.UseDB {
		docID, err := url.PathUnescape(mux.Vars(req)[docIDPathVariable])
		require.NoError(o.T, err)

		delete(o.DB, docID)
	} else {
		_, err := rw.Write(o.DeleteDocumentReturnBody)
		require.NoError(o.T, err)
	}
}

func (o *MockServerOperation) mockUpdateDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(o.UpdateDocumentReturnStatusCode)
	_, err := rw.Write(o.UpdateDocumentReturnBody)
	require.NoError(o.T, err)
}
