/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/internal/jsonldtest"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd, err := context.New(newMockProvider(t))

		require.NotNil(t, cmd)
		require.NoError(t, err)
		require.Len(t, cmd.GetHandlers(), 1)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		storage := mockstorage.NewMockStoreProvider()
		storage.FailNamespace = jsonld.ContextsDBName

		cmd, err := context.New(&mockprovider.Provider{
			StorageProviderValue: storage,
		})

		require.Nil(t, cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open store")
	})
}

func TestCommand_Add(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storage := mockstorage.NewMockStoreProvider()

		cmd, err := context.New(&mockprovider.Provider{
			StorageProviderValue: storage,
		})
		require.NoError(t, err)

		contexts := jsonldtest.Contexts()

		b, err := json.Marshal(context.AddRequest{Documents: contexts})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.Add(&rw, bytes.NewReader(b))

		require.NoError(t, err)
		require.Len(t, storage.Store.Store, len(contexts))
	})

	t.Run("Fail: context URL is mandatory", func(t *testing.T) {
		cmd, err := context.New(newMockProvider(t))
		require.NoError(t, err)

		b, err := json.Marshal(context.AddRequest{Documents: []jsonld.ContextDocument{
			{
				URL:     "",
				Content: jsonldtest.Contexts()[0].Content,
			},
		}})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.Add(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "context URL is mandatory")
	})

	t.Run("Fail: content is mandatory", func(t *testing.T) {
		cmd, err := context.New(newMockProvider(t))
		require.NoError(t, err)

		b, err := json.Marshal(context.AddRequest{Documents: []jsonld.ContextDocument{
			{
				URL:     "https://www.w3.org/2018/credentials/examples/v1",
				Content: nil,
			},
		}})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.Add(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "content is mandatory")
	})

	t.Run("Fail to read context document", func(t *testing.T) {
		cmd, err := context.New(newMockProvider(t))
		require.NoError(t, err)

		b, err := json.Marshal(context.AddRequest{Documents: []jsonld.ContextDocument{
			{
				URL:     "https://www.w3.org/2018/credentials/examples/v1",
				Content: []byte("invalid content"),
			},
		}})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.Add(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "document from reader: loading document failed")
	})

	t.Run("Fail to save contexts", func(t *testing.T) {
		storage := mockstorage.NewMockStoreProvider()
		storage.Store.ErrBatch = errors.New("batch error")

		cmd, err := context.New(&mockprovider.Provider{
			StorageProviderValue: storage,
		})
		require.NoError(t, err)

		b, err := json.Marshal(context.AddRequest{Documents: jsonldtest.Contexts()})
		require.NoError(t, err)

		var rw bytes.Buffer
		err = cmd.Add(&rw, bytes.NewReader(b))

		require.Error(t, err)
		require.Contains(t, err.Error(), "save contexts")
	})
}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	return &mockprovider.Provider{
		StorageProviderValue: mockstorage.NewMockStoreProvider(),
	}
}
