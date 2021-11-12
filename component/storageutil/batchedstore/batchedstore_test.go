/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batchedstore_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/batchedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore/exampleformatters"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestProvider_OpenStore(t *testing.T) {
	t.Run("Failed to open store in underlying provider", func(t *testing.T) {
		provider := batchedstore.NewProvider(&mock.Provider{ErrOpenStore: errors.New("open store failure")},
			3)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in underlying provider: open store failure")
		require.Nil(t, store)
	})
}

func TestProvider_Close(t *testing.T) {
	t.Run("Failed to close open store", func(t *testing.T) {
		provider := batchedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrClose: errors.New("close failure")}}, 3)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.Close()
		require.EqualError(t, err, `failed to close open store with name "storename": `+
			`failed to close underlying store: close failure`)
	})
	t.Run("Failed to close underlying provider", func(t *testing.T) {
		provider := batchedstore.NewProvider(&mock.Provider{ErrClose: errors.New("close failure")}, 3)
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close underlying provider: close failure")
	})
}

func TestCommon(t *testing.T) {
	t.Run("With batch size set to 0", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 0)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(),
					exampleformatters.NewBase64Formatter(true)), 0)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
	})
	t.Run("With batch size set to 1", func(t *testing.T) { // Should work the same as size 0 above
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 1)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(),
					exampleformatters.NewBase64Formatter(true)), 1)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
	})
	t.Run("With batch size set to 2", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 2)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			t.Run("With no-op formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{}), 2)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
			t.Run("With base64 formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(),
						exampleformatters.NewBase64Formatter(true)), 2)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
		})
	})
	t.Run("With batch size set to 10", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 10)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			t.Run("With no-op formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{}), 10)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
			t.Run("With base64 formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(),
						exampleformatters.NewBase64Formatter(true)), 10)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
		})
	})
	t.Run("With batch size set to 100", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 100)
			require.NotNil(t, provider)

			storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			t.Run("With no-op formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{}), 100)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
			t.Run("With base64 formatter", func(t *testing.T) {
				provider := batchedstore.NewProvider(
					formattedstore.NewProvider(mem.NewProvider(),
						exampleformatters.NewBase64Formatter(true)), 100)
				require.NotNil(t, provider)

				storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
			})
		})
	})
}
