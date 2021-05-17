/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	jsonldcontextcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	jsonldcontextrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op, err := jsonldcontextrest.New(&mockprovider.Provider{
			StorageProviderValue: mockstorage.NewMockStoreProvider(),
		})

		require.NotNil(t, op)
		require.NoError(t, err)
		require.Equal(t, 1, len(op.GetRESTHandlers()))
	})

	t.Run("Fail to create jsonld context command", func(t *testing.T) {
		storage := mockstorage.NewMockStoreProvider()
		storage.FailNamespace = jsonld.ContextsDBName

		op, err := jsonldcontextrest.New(&mockprovider.Provider{
			StorageProviderValue: storage,
		})

		require.Nil(t, op)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create jsonld context command")
	})
}

func TestOperation_Add(t *testing.T) {
	op, err := jsonldcontextrest.New(&mockprovider.Provider{
		StorageProviderValue: mockstorage.NewMockStoreProvider(),
	})
	require.NoError(t, err)

	reqBytes, err := json.Marshal(jsonldcontextcmd.AddRequest{
		Documents: jsonldtest.Contexts(),
	})
	require.NoError(t, err)

	handler := lookupHandler(t, op, jsonldcontextrest.AddContextPath, http.MethodPost)
	_, code := sendRequestToHandler(t, handler, bytes.NewBuffer(reqBytes), jsonldcontextrest.AddContextPath)

	require.Equal(t, http.StatusOK, code)
}

func lookupHandler(t *testing.T, op *jsonldcontextrest.Operation, path, method string) rest.Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func sendRequestToHandler(t *testing.T, handler rest.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int) {
	t.Helper()

	// prepare request
	req, err := http.NewRequestWithContext(context.Background(), handler.Method(), path, requestBody)
	require.NoError(t, err)

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code
}
