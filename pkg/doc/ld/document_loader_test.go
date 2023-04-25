/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/embed"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const sampleJSONLDContext = `
{
  "@context": {
    "name": "http://xmlns.com/foaf/0.1/name",
    "homepage": {
      "@id": "http://xmlns.com/foaf/0.1/homepage",
      "@type": "@id"
    }
  }
}`

func TestNewDocumentLoader(t *testing.T) {
	t.Run("Load embedded contexts by default", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)))
		require.NoError(t, err)
		require.NotNil(t, loader)

		require.Equal(t, len(embed.Contexts), len(store.Store.Store))
	})

	t.Run("Extra context replaces embedded context with the same URL", func(t *testing.T) {
		embedContext := embed.Contexts[0]

		extraContext := ldcontext.Document{
			URL:     embedContext.URL,
			Content: json.RawMessage(`{"@context":"extra"}`),
		}

		store := mockldstore.NewMockContextStore()

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)),
			ld.WithExtraContexts(extraContext))
		require.NoError(t, err)
		require.NotNil(t, loader)

		assertContextInStore(t, store.Store, extraContext.URL, "extra")
	})

	t.Run("Load contexts from the remote provider", func(t *testing.T) {
		p := &mockRemoteProvider{
			Documents: []ldcontext.Document{
				{
					URL:     "https://json-ld.org/contexts/context-1.jsonld",
					Content: json.RawMessage(`{"@context":"context-1"}`),
				},
				{
					URL:     "https://json-ld.org/contexts/context-2.jsonld",
					Content: json.RawMessage(`{"@context":"context-2"}`),
				},
			},
		}

		contextStore := mockldstore.NewMockContextStore()
		remoteProviderStore := mockldstore.NewMockRemoteProviderStore()

		loader, err := ld.NewDocumentLoader(createMockProvider(
			withContextStore(contextStore),
			withRemoteProviderStore(remoteProviderStore),
		), ld.WithRemoteProvider(p))
		require.NoError(t, err)
		require.NotNil(t, loader)

		require.Equal(t, len(embed.Contexts)+2, len(contextStore.Store.Store))
		require.Equal(t, 1, len(remoteProviderStore.Store.Store))
	})

	t.Run("Fail to get contexts from the remote provider", func(t *testing.T) {
		loader, err := ld.NewDocumentLoader(createMockProvider(),
			ld.WithRemoteProvider(&mockRemoteProvider{ErrContexts: errors.New("contexts error")}))

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get provider contexts")
	})

	t.Run("Fail to save remote provider", func(t *testing.T) {
		p := &mockRemoteProvider{
			Documents: []ldcontext.Document{
				{
					URL:     "https://json-ld.org/contexts/context-1.jsonld",
					Content: json.RawMessage(`{"@context":"context-1"}`),
				},
			},
		}

		store := mockldstore.NewMockRemoteProviderStore()
		store.ErrSave = errors.New("save error")

		loader, err := ld.NewDocumentLoader(createMockProvider(withRemoteProviderStore(store)),
			ld.WithRemoteProvider(p))

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save remote provider")
	})

	t.Run("Fail to import contexts", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.ErrImport = errors.New("import error")

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)))

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "import contexts")
	})
}

func TestLoadDocument(t *testing.T) {
	t.Run("Load context from store", func(t *testing.T) {
		c, err := jsonld.DocumentFromReader(strings.NewReader(sampleJSONLDContext))
		require.NotNil(t, c)
		require.NoError(t, err)

		b, err := json.Marshal(&jsonld.RemoteDocument{
			DocumentURL: "https://example.com/context.jsonld",
			Document:    c,
		})
		require.NoError(t, err)

		store := mockldstore.NewMockContextStore()
		store.Store.Store = map[string]mockstorage.DBEntry{
			"https://example.com/context.jsonld": {
				Value: b,
			},
		}

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.NotNil(t, rd)
		require.NoError(t, err)
	})

	t.Run("Fetch remote context document and import into store", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.Store.ErrGet = storage.ErrDataNotFound

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)),
			ld.WithRemoteDocumentLoader(&mockRemoteDocumentLoader{}))

		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.NotNil(t, rd)
		require.NoError(t, err)

		require.NotNil(t, store.Store.Store["https://example.com/context.jsonld"])
	})

	t.Run("ErrContextNotFound if no context document found in a store", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.Store.ErrGet = storage.ErrDataNotFound

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.EqualError(t, err, ld.ErrContextNotFound.Error())
	})

	t.Run("Fail to get context from store", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.Store.ErrGet = errors.New("get error")

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load document")
	})

	t.Run("Fail to load remote context document", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()
		store.Store.ErrGet = storage.ErrDataNotFound

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)),
			ld.WithRemoteDocumentLoader(&mockRemoteDocumentLoader{ErrLoadDocument: errors.New("load document error")}))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load remote context document")
	})

	t.Run("Fail to save fetched remote document", func(t *testing.T) {
		store := mockldstore.NewMockContextStore()

		loader, err := ld.NewDocumentLoader(createMockProvider(withContextStore(store)),
			ld.WithRemoteDocumentLoader(&mockRemoteDocumentLoader{}))
		require.NotNil(t, loader)
		require.NoError(t, err)

		store.Store.ErrGet = storage.ErrDataNotFound
		store.Store.ErrPut = errors.New("put error")

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save loaded document")
	})
}

func assertContextInStore(t *testing.T, store storage.Store, url, value string) {
	t.Helper()

	b, err := store.Get(url)
	require.NoError(t, err)

	var rd jsonld.RemoteDocument

	err = json.Unmarshal(b, &rd)
	require.NoError(t, err)

	require.Equal(t, value, rd.Document.(map[string]interface{})["@context"])
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

type mockRemoteDocumentLoader struct {
	ErrLoadDocument error
}

func (m *mockRemoteDocumentLoader) LoadDocument(string) (*jsonld.RemoteDocument, error) {
	if m.ErrLoadDocument != nil {
		return nil, m.ErrLoadDocument
	}

	document, err := jsonld.DocumentFromReader(strings.NewReader(sampleJSONLDContext))
	if err != nil {
		return nil, err
	}

	return &jsonld.RemoteDocument{
		DocumentURL: "https://example.com/context.jsonld",
		Document:    document,
	}, nil
}

type mockRemoteProvider struct {
	Documents   []ldcontext.Document
	ErrContexts error
}

func (m *mockRemoteProvider) Endpoint() string {
	return "endpoint"
}

func (m *mockRemoteProvider) Contexts() ([]ldcontext.Document, error) {
	if m.ErrContexts != nil {
		return nil, m.ErrContexts
	}

	return m.Documents, nil
}
