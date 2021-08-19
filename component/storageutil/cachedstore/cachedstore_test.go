/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cachedstore_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	commonstoragetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func Test_Common(t *testing.T) {
	commonstoragetest.TestAll(t,
		cachedstore.NewProvider(mem.NewProvider(), mem.NewProvider()),
		commonstoragetest.SkipSortTests(false))
}

func TestCachedProvider_OpenStore(t *testing.T) {
	t.Run("Fail to open store in the main provider", func(t *testing.T) {
		cachedProvider := cachedstore.NewProvider(&mock.Provider{
			ErrOpenStore: errors.New("open store failure"),
		}, mem.NewProvider())

		store, err := cachedProvider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in main provider: open store failure")
		require.Nil(t, store)
	})
	t.Run("Fail to open store in the cache provider", func(t *testing.T) {
		cachedProvider := cachedstore.NewProvider(mem.NewProvider(),
			&mock.Provider{
				ErrOpenStore: errors.New("open store failure"),
			})

		store, err := cachedProvider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in cache provider: open store failure")
		require.Nil(t, store)
	})
}

func TestCachedProvider_SetStoreConfig(t *testing.T) {
	t.Run("Fail to set the store config in the cache provider", func(t *testing.T) {
		mainProvider := mem.NewProvider()

		_, err := mainProvider.OpenStore("StoreName")
		require.NoError(t, err)

		cachedProvider := cachedstore.NewProvider(mainProvider,
			&mock.Provider{
				ErrSetStoreConfig: errors.New("set config failure"),
			})

		err = cachedProvider.SetStoreConfig("StoreName", spi.StoreConfiguration{})
		require.EqualError(t, err, "failed to set store configuration in cache provider: set config failure")
	})
}

func TestCachedProvider_Close(t *testing.T) {
	t.Run("Fail to close the main provider", func(t *testing.T) {
		provider := cachedstore.NewProvider(&mock.Provider{ErrClose: errors.New("close failure")}, mem.NewProvider())

		err := provider.Close()
		require.EqualError(t, err, "failed to close main provider: close failure")
	})
	t.Run("Fail to close the cache provider", func(t *testing.T) {
		provider := cachedstore.NewProvider(mem.NewProvider(),
			&mock.Provider{ErrClose: errors.New("close failure")})

		err := provider.Close()
		require.EqualError(t, err, "failed to close cache provider: close failure")
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("Fail to put data in the cache store", func(t *testing.T) {
		provider := cachedstore.NewProvider(mem.NewProvider(),
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrPut: errors.New("put failure")}})

		store, err := provider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Put("key", []byte("value"))
		require.EqualError(t, err, "failed to put key, values and tags in the cache store: put failure")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("Fail to put newly retrieved data into the cache store", func(t *testing.T) {
		mainProvider := mem.NewProvider()

		mainStore, err := mainProvider.OpenStore("TestStore")
		require.NoError(t, err)

		err = mainStore.Put("key", []byte("value"))
		require.NoError(t, err)

		provider := cachedstore.NewProvider(mainProvider,
			&mock.Provider{OpenStoreReturn: &mock.Store{
				ErrGet: spi.ErrDataNotFound, ErrPut: errors.New("put failure"),
			}})

		store, err := provider.OpenStore("TestStore")
		require.NoError(t, err)

		_, err = store.Get("key")
		require.EqualError(t, err,
			"failed to put the newly retrieved data into the cache store for future use: put failure")
	})
}

func TestStore_Close(t *testing.T) {
	t.Run("Fail to close the main store", func(t *testing.T) {
		provider := cachedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrClose: errors.New("close failure")}}, mem.NewProvider())

		store, err := provider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Close()
		require.EqualError(t, err, "failed to close the main store: close failure")
	})
	t.Run("Fail to close the cache store", func(t *testing.T) {
		provider := cachedstore.NewProvider(
			mem.NewProvider(), &mock.Provider{OpenStoreReturn: &mock.Store{ErrClose: errors.New("close failure")}})

		store, err := provider.OpenStore("TestStore")
		require.NoError(t, err)

		err = store.Close()
		require.EqualError(t, err, "failed to close the cache store: close failure")
	})
}
