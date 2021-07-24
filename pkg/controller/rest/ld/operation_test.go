/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	sampleContextsResponse = `{
  "documents": [
    {
      "url": "https://example.com/context.jsonld",
      "content": {
        "@context": "remote"
      }
    }
  ]
}`
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := ldrest.New(createMockProvider(), &mockHTTPClient{})

		require.NotNil(t, op)
		require.Equal(t, 6, len(op.GetRESTHandlers()))
	})
}

func TestOperation_AddContexts(t *testing.T) {
	op := ldrest.New(createMockProvider(), &mockHTTPClient{})
	require.NotNil(t, op)

	reqBytes, err := json.Marshal(ldcmd.AddContextsRequest{
		Documents: ldtestutil.Contexts(),
	})
	require.NoError(t, err)

	handler := lookupHandler(t, op, ldrest.AddContextsPath, http.MethodPost)
	_, code := sendRequestToHandler(t, handler, bytes.NewBuffer(reqBytes), ldrest.AddContextsPath)

	require.Equal(t, http.StatusOK, code)
}

func TestOperation_AddRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}

	op := ldrest.New(createMockProvider(), httpClient)
	require.NotNil(t, op)

	reqBytes, err := json.Marshal(ldcmd.AddRemoteProviderRequest{
		Endpoint: "endpoint",
	})
	require.NoError(t, err)

	handler := lookupHandler(t, op, ldrest.AddRemoteProviderPath, http.MethodPost)
	respBody, code := sendRequestToHandler(t, handler, bytes.NewBuffer(reqBytes), ldrest.AddRemoteProviderPath)

	require.Equal(t, http.StatusOK, code)

	var resp ldcmd.ProviderID

	err = json.Unmarshal(respBody.Bytes(), &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.ID)
}

func TestOperation_RefreshRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}

	store := mockldstore.NewMockRemoteProviderStore()
	store.Store.Store["id"] = mockstorage.DBEntry{
		Value: []byte("endpoint"),
		Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
	}

	op := ldrest.New(createMockProvider(withRemoteProviderStore(store)), httpClient)
	require.NotNil(t, op)

	handler := lookupHandler(t, op, ldrest.RefreshRemoteProviderPath, http.MethodPost)
	_, code := sendRequestToHandler(t, handler, nil, strings.Replace(ldrest.RefreshRemoteProviderPath, "{id}", "id", 1))

	require.Equal(t, http.StatusOK, code)
}

func TestOperation_DeleteRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}

	store := mockldstore.NewMockRemoteProviderStore()
	store.Store.Store["id"] = mockstorage.DBEntry{
		Value: []byte("endpoint"),
		Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
	}

	op := ldrest.New(createMockProvider(withRemoteProviderStore(store)), httpClient)
	require.NotNil(t, op)

	handler := lookupHandler(t, op, ldrest.DeleteRemoteProviderPath, http.MethodDelete)
	_, code := sendRequestToHandler(t, handler, nil, strings.Replace(ldrest.DeleteRemoteProviderPath, "{id}", "id", 1))

	require.Equal(t, http.StatusOK, code)
}

func TestOperation_GetRemoteProviders(t *testing.T) {
	store := mockldstore.NewMockRemoteProviderStore()
	store.Store.Store["id"] = mockstorage.DBEntry{
		Value: []byte("endpoint"),
		Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
	}

	op := ldrest.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})
	require.NotNil(t, op)

	handler := lookupHandler(t, op, ldrest.GetAllRemoteProvidersPath, http.MethodGet)
	respBody, code := sendRequestToHandler(t, handler, nil, ldrest.GetAllRemoteProvidersPath)

	require.Equal(t, http.StatusOK, code)

	var resp ldcmd.GetAllRemoteProvidersResponse

	err := json.Unmarshal(respBody.Bytes(), &resp)
	require.NoError(t, err)

	require.Equal(t, 1, len(resp.Providers))
	require.Equal(t, "id", resp.Providers[0].ID)
	require.Equal(t, "endpoint", resp.Providers[0].Endpoint)
}

func TestOperation_RefreshRemoteProviders(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}

	store := mockldstore.NewMockRemoteProviderStore()
	store.Store.Store["id"] = mockstorage.DBEntry{
		Value: []byte("endpoint"),
		Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
	}

	op := ldrest.New(createMockProvider(withRemoteProviderStore(store)), httpClient)
	require.NotNil(t, op)

	handler := lookupHandler(t, op, ldrest.RefreshAllRemoteProvidersPath, http.MethodPost)
	_, code := sendRequestToHandler(t, handler, nil, ldrest.RefreshAllRemoteProvidersPath)

	require.Equal(t, http.StatusOK, code)
}

func lookupHandler(t *testing.T, op *ldrest.Operation, path, method string) rest.Handler {
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

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func createMockProvider(opts ...providerOptionFn) *mockprovider.Provider {
	p := &mockprovider.Provider{
		ContextStoreValue:        mockldstore.NewMockContextStore(),
		RemoteProviderStoreValue: mockldstore.NewMockRemoteProviderStore(),
	}

	for i := range opts {
		opts[i](p)
	}

	return p
}

type providerOptionFn func(opts *mockprovider.Provider)

func withRemoteProviderStore(store ld.RemoteProviderStore) providerOptionFn {
	return func(p *mockprovider.Provider) {
		p.RemoteProviderStoreValue = store
	}
}
