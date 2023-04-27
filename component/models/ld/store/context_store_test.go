/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/context/embed"
	ldstore "github.com/hyperledger/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	sampleJSONLDContext = `
{
  "@context": {
    "name": "http://xmlns.com/foaf/0.1/name",
    "homepage": {
      "@id": "http://xmlns.com/foaf/0.1/homepage",
      "@type": "@id"
    }
  }
}`
	sampleContextURL = "https://example.com/context.jsonld"
)

func TestNewContextStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		store, err := ldstore.NewContextStore(storageProvider)

		require.NoError(t, err)
		require.NotNil(t, store)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.ErrOpenStoreHandle = errors.New("open store error")
		storageProvider.ErrSetStoreConfig = errors.New("set store config error")

		store, err := ldstore.NewContextStore(storageProvider)

		require.Nil(t, store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open store")
	})

	t.Run("Fail to set store config", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.ErrSetStoreConfig = errors.New("set store config error")

		store, err := ldstore.NewContextStore(storageProvider)

		require.Nil(t, store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "set store config")
	})
}

func TestContextStoreImpl_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		setSampleContextInStore(t, storageProvider.Store)

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		rd, err := contextStore.Get("https://example.com/context.jsonld")

		require.NoError(t, err)
		require.NotNil(t, rd)
	})

	t.Run("Fail to get context from store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = errors.New("get error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		rd, err := contextStore.Get("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get context from store")
	})
}

func TestContextStoreImpl_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		rd := getRemoteDocument(t, json.RawMessage(sampleJSONLDContext))

		err = contextStore.Put("https://example.com/context.jsonld", rd)

		require.NoError(t, err)
		require.Equal(t, 1, len(storageProvider.Store.Store))
	})

	t.Run("Fail to put remote document", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrPut = errors.New("put error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		rd := getRemoteDocument(t, json.RawMessage(sampleJSONLDContext))

		err = contextStore.Put("https://example.com/context.jsonld", rd)

		require.Error(t, err)
		require.Contains(t, err.Error(), "put remote document")
	})
}

func TestContextStoreImpl_Import(t *testing.T) {
	t.Run("Import up-to-date contexts only once", func(t *testing.T) {
		store := &mockStore{
			MockStore: &mockstorage.MockStore{
				Store: make(map[string]mockstorage.DBEntry),
			},
		}

		storageProvider := &mockstorage.MockStoreProvider{Custom: store}

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.NoError(t, err)
		require.Equal(t, len(embed.Contexts), len(store.Store))

		store.BatchSize = 0

		err = contextStore.Import(embed.Contexts) // import the same contexts again
		require.NoError(t, err)

		require.Equal(t, 0, store.BatchSize)
		require.Equal(t, len(embed.Contexts), len(store.Store))
	})

	t.Run("Import outdated contexts", func(t *testing.T) {
		store := &mockStore{
			MockStore: &mockstorage.MockStore{
				Store: make(map[string]mockstorage.DBEntry),
			},
		}

		storageProvider := &mockstorage.MockStoreProvider{Custom: store}

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(`{"@context":"original-context"}`),
			},
		}

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(contexts)
		require.NoError(t, err)

		assertContextInStore(t, store, sampleContextURL, "original-context")

		contexts[0].Content = json.RawMessage(`{"@context":"updated-context"}`)

		err = contextStore.Import(contexts)
		require.NoError(t, err)

		assertContextInStore(t, store, sampleContextURL, "updated-context")
	})

	t.Run("Fail to query store for contexts", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrQuery = errors.New("query error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query store")
	})

	t.Run("Fail to get next entry while iterating over query set", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrNext = errors.New("next error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next entry")
	})

	t.Run("Fail to get key from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrKey = errors.New("key error")

		setSampleContextInStore(t, storageProvider.Store)

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get key")
	})

	t.Run("Fail to get value from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		setSampleContextInStore(t, storageProvider.Store)

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get value")
	})

	t.Run("Fail to read context document file", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import([]ldcontext.Document{
			{
				URL:     "url",
				Content: nil,
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "document from reader")
	})

	t.Run("Fail to store batch of context documents", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrPut = errors.New("error")

		contextStore, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		err = contextStore.Import(embed.Contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store context: error")
	})
}

func TestContextStoreImpl_Delete(t *testing.T) {
	t.Run("Delete matched contexts", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		setSampleContextInStore(t, storageProvider.Store)

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Delete(contexts)
		require.NoError(t, err)
		require.Equal(t, 0, len(storageProvider.Store.Store))
	})

	t.Run("Fail to query store for contexts", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrQuery = errors.New("query error")

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Delete(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query store")
	})

	t.Run("Fail to get next entry while iterating over query set", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrNext = errors.New("next error")

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Delete(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next entry")
	})

	t.Run("Fail to get key from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrKey = errors.New("key error")

		setSampleContextInStore(t, storageProvider.Store)

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Delete(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get key")
	})

	t.Run("Fail to get value from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		setSampleContextInStore(t, storageProvider.Store)

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Import(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get value")
	})

	t.Run("Fail to read context document file", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: nil,
			},
		}

		err = store.Delete(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "document from reader")
	})

	t.Run("Fail to delete context document", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrDelete = errors.New("delete error")

		setSampleContextInStore(t, storageProvider.Store)

		store, err := ldstore.NewContextStore(storageProvider)
		require.NoError(t, err)

		contexts := []ldcontext.Document{
			{
				URL:     sampleContextURL,
				Content: json.RawMessage(sampleJSONLDContext),
			},
		}

		err = store.Delete(contexts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete context document")
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

func setSampleContextInStore(t *testing.T, store storage.Store) {
	t.Helper()

	rd := getRemoteDocument(t, json.RawMessage(sampleJSONLDContext))

	b, err := json.Marshal(rd)
	require.NoError(t, err)

	err = store.Put(sampleContextURL, b, storage.Tag{Name: ldstore.ContextRecordTag})
	require.NoError(t, err)
}

func getRemoteDocument(t *testing.T, content json.RawMessage) *jsonld.RemoteDocument {
	t.Helper()

	document, err := jsonld.DocumentFromReader(bytes.NewReader(content))
	require.NoError(t, err)

	return &jsonld.RemoteDocument{Document: document}
}

type mockStore struct {
	*mockstorage.MockStore
	BatchSize int
}

func (s *mockStore) Batch(operations []storage.Operation) error {
	s.BatchSize = len(operations)

	return s.MockStore.Batch(operations)
}
