/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockld "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

const sampleContextsResponse = `{
  "documents": [
    {
      "url": "https://example.com/context.jsonld",
      "content": {
        "@context": "remote"
      }
    }
  ]
}`

func TestClient_AddContexts(t *testing.T) {
	c := createLDClient(t)

	err := c.AddContexts(ldtestutil.Contexts())
	require.NoError(t, err)
}

func TestClient_AddRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}
	c := createLDClient(t)

	_, err := c.AddRemoteProvider("endpoint", remote.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func TestClient_RefreshRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}
	c := createLDClient(t)

	err := c.RefreshRemoteProvider("id", remote.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func TestClient_DeleteRemoteProvider(t *testing.T) {
	httpClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}
	c := createLDClient(t)

	err := c.DeleteRemoteProvider("id", remote.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func TestClient_GetAllRemoteProviders(t *testing.T) {
	c := createLDClient(t)

	_, err := c.GetAllRemoteProviders()
	require.NoError(t, err)
}

func TestClient_RefreshAllRemoteProviders(t *testing.T) {
	httpClient := createHTTPClient()
	c := createLDClient(t)

	err := c.RefreshAllRemoteProviders(remote.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func createLDClient(t *testing.T) *ld.Client {
	t.Helper()

	c := ld.NewClient(createMockProvider(), ld.WithLDService(&mockld.MockService{}))
	require.NotNil(t, c)

	return c
}

func createMockProvider() *mockprovider.Provider {
	return &mockprovider.Provider{
		ContextStoreValue:        mockld.NewMockContextStore(),
		RemoteProviderStoreValue: mockld.NewMockRemoteProviderStore(),
	}
}

func createHTTPClient() *mockHTTPClient {
	return &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
			}, nil
		},
	}
}

type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
