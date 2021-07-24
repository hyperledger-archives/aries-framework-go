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
	"strings"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
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

func TestCommand_GetHandlers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := ldcmd.New(createMockProvider(), &mockHTTPClient{})
		require.Equal(t, 6, len(cmd.GetHandlers()))
	})
}

func TestCommand_AddContexts(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()

		cmd := ldcmd.New(createMockProvider(withContextStore(store)), &mockHTTPClient{})

		contexts := ldtestutil.Contexts()

		b, err := json.Marshal(ldcmd.AddContextsRequest{Documents: contexts})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddContexts(&rw, bytes.NewReader(b))

		require.NoError(t, err)
		require.Len(t, store.Store.Store, len(contexts))
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(createMockProvider(), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.AddContexts(&rw, strings.NewReader("invalid request"))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to import contexts", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.ErrImport = errors.New("import error")

		cmd := ldcmd.New(createMockProvider(withContextStore(store)), &mockHTTPClient{})

		context := ldtestutil.Contexts()[0]

		b, err := json.Marshal(ldcmd.AddContextsRequest{
			Documents: []ldcontext.Document{
				{
					URL:     context.URL,
					Content: context.Content,
				},
			},
		})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddContexts(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestCommand_AddRemoteProvider(t *testing.T) {
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
		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

		require.NoError(t, err)
		require.Equal(t, 1, len(remoteProviderStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(createMockProvider(), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.AddRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to get contexts from remote provider", func(t *testing.T) {
		httpClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte(""))),
				}, nil
			},
		}

		cmd := ldcmd.New(createMockProvider(), httpClient)

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.ErrSave = errors.New("save error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(remoteProviderStore)), httpClient)

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

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

		cmd := ldcmd.New(createMockProvider(withContextStore(contextStore)), httpClient)

		b, err := json.Marshal(ldcmd.AddRemoteProviderRequest{Endpoint: "endpoint"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.AddRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestCommand_RefreshRemoteProvider(t *testing.T) {
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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

		require.NoError(t, err)
		require.Equal(t, 1, len(remoteProviderStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(createMockProvider(), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.RefreshRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to get remote provider from store", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGet = errors.New("get error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(remoteProviderStore)), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.RefreshRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestCommand_DeleteRemoteProvider(t *testing.T) {
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
			Tags:  []storage.Tag{{Name: ld.ContextRecordTag}},
		}

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		reqBytes, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(reqBytes))

		require.NoError(t, err)
		require.Equal(t, 0, len(remoteProviderStore.Store.Store))
		require.Equal(t, 0, len(contextStore.Store.Store))
	})

	t.Run("Fail to decode request", func(t *testing.T) {
		cmd := ldcmd.New(createMockProvider(), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.DeleteRemoteProvider(&rw, bytes.NewReader([]byte("invalid request")))

		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("Fail to get remote provider from store", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGet = errors.New("get error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(b))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(remoteProviderStore)), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(b))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(b))

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
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}
		store.ErrDelete = errors.New("delete error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), httpClient)

		b, err := json.Marshal(ldcmd.ProviderID{ID: "id"})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.DeleteRemoteProvider(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "delete remote provider record:")
	})
}

func TestCommand_GetAllRemoteProviders(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.GetAllRemoteProviders(&rw, bytes.NewReader(nil))

		var resp ldcmd.GetAllRemoteProvidersResponse

		e := json.Unmarshal(rw.Bytes(), &resp)
		require.NoError(t, e)

		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Providers))
	})

	t.Run("Fail to get remote provider records", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGetAll = errors.New("get all error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.GetAllRemoteProviders(&rw, bytes.NewReader(nil))

		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider records")
	})
}

func TestCommand_RefreshAllRemoteProviders(t *testing.T) {
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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

		require.NoError(t, err)
		require.Equal(t, 1, len(remoteProviderStore.Store.Store))
		require.Equal(t, 1, len(contextStore.Store.Store))
	})

	t.Run("Fail to get remote provider records", func(t *testing.T) {
		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrGetAll = errors.New("get all error")

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), &mockHTTPClient{})

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

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
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(withRemoteProviderStore(store)), httpClient)

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

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

		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()
		remoteProviderStore.Store.Store["id"] = mockstorage.DBEntry{
			Value: []byte("endpoint"),
			Tags:  []storage.Tag{{Name: ld.RemoteProviderRecordTag}},
		}

		cmd := ldcmd.New(createMockProvider(
			withContextStore(store),
			withRemoteProviderStore(remoteProviderStore),
		), httpClient)

		var rw bytes.Buffer
		err := cmd.RefreshAllRemoteProviders(&rw, bytes.NewReader(nil))

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

func withContextStore(store ld.ContextStore) providerOptionFn {
	return func(p *mockprovider.Provider) {
		p.ContextStoreValue = store
	}
}

func withRemoteProviderStore(store ld.RemoteProviderStore) providerOptionFn {
	return func(p *mockprovider.Provider) {
		p.RemoteProviderStoreValue = store
	}
}
