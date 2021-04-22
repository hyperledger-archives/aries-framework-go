/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestNewDocumentLoader(t *testing.T) {
	t.Run("Preload default embedded contexts", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		loader, err := jsonld.NewDocumentLoader(storageProvider)

		require.NotNil(t, loader)
		require.NoError(t, err)
		require.Equal(t, len(jsonld.EmbedContexts), len(storageProvider.Store.Store))
	})

	t.Run("Fail to open context DB store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.FailNamespace = "invalidDB"

		loader, err := jsonld.NewDocumentLoader(storageProvider, jsonld.WithContextDBName("invalidDB"))

		require.Nil(t, loader)
		require.Error(t, err)
	})

	t.Run("Fail to open context document file", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		loader, err := jsonld.NewDocumentLoader(storageProvider,
			jsonld.WithContextFS(&mockFS{ErrOpen: errors.New("open error")}))

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open file")
	})

	t.Run("Fail to read context document file", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		loader, err := jsonld.NewDocumentLoader(storageProvider,
			jsonld.WithContextFS(&mockFS{ErrRead: errors.New("read error")}))

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load from FS")
	})

	t.Run("Fail to store batch of context documents", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrBatch = errors.New("batch error")

		loader, err := jsonld.NewDocumentLoader(storageProvider)

		require.Nil(t, loader)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store batch of contexts")
	})
}

func TestLoadDocument(t *testing.T) {
	t.Run("Load context from store", func(t *testing.T) {
		c, err := ld.DocumentFromReader(strings.NewReader(sampleJSONLDContext))
		require.NotNil(t, c)
		require.NoError(t, err)

		b, err := json.Marshal(&ld.RemoteDocument{
			DocumentURL: "https://example.com/context.jsonld",
			Document:    c,
		})
		require.NoError(t, err)

		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.Store = map[string]mockstorage.DBEntry{
			"https://example.com/context.jsonld": {
				Value: b,
			},
		}

		loader, err := jsonld.NewDocumentLoader(storageProvider)
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.NotNil(t, rd)
		require.NoError(t, err)
	})

	t.Run("Fetch remote context document and import into store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = storage.ErrDataNotFound

		loader, err := jsonld.NewDocumentLoader(storageProvider,
			jsonld.WithRemoteDocumentLoader(&mockDocumentLoader{}))

		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.NotNil(t, rd)
		require.NoError(t, err)

		require.NotNil(t, storageProvider.Store.Store["https://example.com/context.jsonld"])
	})

	t.Run("ErrContextNotFound if no context document in store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = storage.ErrDataNotFound

		loader, err := jsonld.NewDocumentLoader(storageProvider)
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.EqualError(t, err, jsonld.ErrContextNotFound.Error())
	})

	t.Run("Fail to get context from store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = errors.New("get error")

		loader, err := jsonld.NewDocumentLoader(storageProvider)
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
	})

	t.Run("Fail to load remote context document", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = storage.ErrDataNotFound

		loader, err := jsonld.NewDocumentLoader(storageProvider,
			jsonld.WithRemoteDocumentLoader(&mockDocumentLoader{ErrLoadDocument: errors.New("load document error")}))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "load remote context document")
	})

	t.Run("Fail to save fetched remote document", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = storage.ErrDataNotFound
		storageProvider.Store.ErrPut = errors.New("put error")

		loader, err := jsonld.NewDocumentLoader(storageProvider,
			jsonld.WithRemoteDocumentLoader(&mockDocumentLoader{}))
		require.NotNil(t, loader)
		require.NoError(t, err)

		rd, err := loader.LoadDocument("https://example.com/context.jsonld")

		require.Nil(t, rd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save remote document")
	})
}

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

type mockDocumentLoader struct {
	ErrLoadDocument error
}

func (m *mockDocumentLoader) LoadDocument(string) (*ld.RemoteDocument, error) {
	if m.ErrLoadDocument != nil {
		return nil, m.ErrLoadDocument
	}

	content, err := ld.DocumentFromReader(strings.NewReader(sampleJSONLDContext))
	if err != nil {
		return nil, err
	}

	return &ld.RemoteDocument{
		DocumentURL: "https://example.com/context.jsonld",
		Document:    content,
	}, nil
}

type mockFS struct {
	ErrOpen error
	ErrRead error
}

func (m *mockFS) Open(string) (fs.File, error) {
	if m.ErrOpen != nil {
		return nil, m.ErrOpen
	}

	return &mockFile{
		ErrRead: m.ErrRead,
	}, nil
}

type mockFile struct {
	ErrRead error
}

func (m *mockFile) Stat() (fs.FileInfo, error) {
	panic("not implemented")
}

func (m *mockFile) Read([]byte) (int, error) {
	return 0, m.ErrRead
}

func (m *mockFile) Close() error {
	return nil
}
