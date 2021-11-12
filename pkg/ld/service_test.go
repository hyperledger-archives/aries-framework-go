/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/ld"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
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

func TestDefaultService_AddContexts(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()

		svc := ld.New(createMockProvider(withContextStore(store)))

		err := svc.AddContexts(ldtestutil.Contexts())

		require.NoError(t, err)
		require.Len(t, store.Store.Store, len(ldtestutil.Contexts()))
	})

	t.Run("Fail to add contexts", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.ErrImport = errors.New("import error")

		svc := ld.New(createMockProvider(withContextStore(store)))

		err := svc.AddContexts(ldtestutil.Contexts())

		require.Error(t, err)
		require.Contains(t, err.Error(), "add contexts")
	})
}

func TestDefaultService_AddRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()
		providerStore := mockldstore.NewMockRemoteProviderStore()

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		providerID, err := svc.AddRemoteProvider("endpoint", remote.WithHTTPClient(httpClient))

		require.NotEmpty(t, providerID)
		require.NoError(t, err)
		require.Equal(t, 1, len(providerStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to get contexts from remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
		}

		svc := ld.New(createMockProvider())

		providerID, err := svc.AddRemoteProvider("endpoint", remote.WithHTTPClient(httpClient))

		require.Empty(t, providerID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get contexts from remote provider")
	})

	t.Run("Fail to save remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.ErrSave = errors.New("save error")

		svc := ld.New(createMockProvider(withRemoteProviderStore(providerStore)))

		providerID, err := svc.AddRemoteProvider("endpoint", remote.WithHTTPClient(httpClient))

		require.Empty(t, providerID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save remote provider")
	})

	t.Run("Fail to import contexts", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()
		contextStore.ErrImport = errors.New("import error")

		svc := ld.New(createMockProvider(withContextStore(contextStore)))

		providerID, err := svc.AddRemoteProvider("endpoint", remote.WithHTTPClient(httpClient))

		require.Empty(t, providerID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestDefaultService_RefreshAllRemoteProviders(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		err := svc.RefreshRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.NoError(t, err)
		require.Equal(t, 1, len(providerStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to get remote provider from store", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGet = errors.New("get error")

		svc := ld.New(createMockProvider(withRemoteProviderStore(store)))

		err := svc.RefreshRemoteProvider("id", remote.WithHTTPClient(&mockHTTPClient{}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider from store")
	})

	t.Run("Fail to get contexts from remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
		}

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(withRemoteProviderStore(providerStore)))

		err := svc.RefreshRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get contexts from remote provider")
	})

	t.Run("Fail to import contexts", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()
		contextStore.ErrImport = errors.New("import error")

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		err := svc.RefreshRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestDefaultService_DeleteRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		document, err := jsonld.DocumentFromReader(bytes.NewReader([]byte(`{"@context": "remote"}`)))
		require.NoError(t, err)

		rd := jsonld.RemoteDocument{
			DocumentURL: "https://example.com/context.jsonld",
			Document:    document,
		}

		b, err := json.Marshal(rd)
		require.NoError(t, err)

		contextStore := mockldstore.NewMockContextStore()
		contextStore.Store.Store[rd.DocumentURL] = mockstorage.DBEntry{
			Value: b,
			Tags:  []storage.Tag{{Name: ldstore.ContextRecordTag}},
		}

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		err = svc.DeleteRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.NoError(t, err)
		require.Equal(t, 0, len(providerStore.Store.Store))
		require.Equal(t, 0, len(contextStore.Store.Store))
	})

	t.Run("Fail to get remote provider from store", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGet = errors.New("get error")

		svc := ld.New(createMockProvider(withRemoteProviderStore(store)))

		err := svc.DeleteRemoteProvider("id", remote.WithHTTPClient(&mockHTTPClient{}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider from store")
	})

	t.Run("Fail to get contexts from remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
		}

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(withRemoteProviderStore(providerStore)))

		err := svc.DeleteRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get contexts from remote provider")
	})

	t.Run("Fail to delete contexts", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()
		contextStore.ErrDelete = errors.New("delete error")

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		err := svc.DeleteRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "delete contexts")
	})

	t.Run("Fail to delete remote provider record", func(t *testing.T) {
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
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}
		store.ErrDelete = errors.New("delete error")

		svc := ld.New(createMockProvider(withRemoteProviderStore(store)))

		err := svc.DeleteRemoteProvider("id", remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "delete remote provider record:")
	})
}

func TestDefaultService_GetAllRemoteProviders(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		cmd := ld.New(createMockProvider(withRemoteProviderStore(store)))

		providers, err := cmd.GetAllRemoteProviders()

		require.NoError(t, err)
		require.Equal(t, 1, len(providers))
	})

	t.Run("Fail to get remote provider records", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGetAll = errors.New("get all error")

		cmd := ld.New(createMockProvider(withRemoteProviderStore(store)))

		providers, err := cmd.GetAllRemoteProviders()

		require.Nil(t, providers)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider records")
	})
}

func TestDefaultService_RefreshRemoteProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		contextStore := mockldstore.NewMockContextStore()

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(providerStore),
		))

		err := svc.RefreshAllRemoteProviders(remote.WithHTTPClient(httpClient))

		require.NoError(t, err)
		require.Equal(t, 1, len(providerStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to get remote provider records", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGetAll = errors.New("get all error")

		svc := ld.New(createMockProvider(withRemoteProviderStore(store)))

		err := svc.RefreshAllRemoteProviders(remote.WithHTTPClient(&mockHTTPClient{}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider records")
	})

	t.Run("Fail to get contexts from remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader(nil)),
				}, nil
			},
		}

		store := mockldstore.NewMockRemoteProviderStore()
		store.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(withRemoteProviderStore(store)))

		err := svc.RefreshAllRemoteProviders(remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get contexts from remote provider")
	})

	t.Run("Fail to import contexts", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(sampleContextsResponse))),
				}, nil
			},
		}

		store := mockldstore.NewMockContextStore()
		store.ErrImport = errors.New("import error")

		providerStore := mockldstore.NewMockRemoteProviderStore()
		providerStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ldstore.RemoteProviderRecordTag}},
		}

		svc := ld.New(createMockProvider(
			withContextStore(store),
			withRemoteProviderStore(providerStore),
		))

		err := svc.RefreshAllRemoteProviders(remote.WithHTTPClient(httpClient))

		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
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

func withContextStore(store ldstore.ContextStore) providerOptionFn {
	return func(p *mockprovider.Provider) {
		p.ContextStoreValue = store
	}
}

func withRemoteProviderStore(store ldstore.RemoteProviderStore) providerOptionFn {
	return func(p *mockprovider.Provider) {
		p.RemoteProviderStoreValue = store
	}
}
