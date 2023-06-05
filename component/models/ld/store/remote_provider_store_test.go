/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package store

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestNewRemoteProviderStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		store, err := NewRemoteProviderStore(storageProvider)

		require.NoError(t, err)
		require.NotNil(t, store)
	})

	t.Run("Fail to open store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.ErrOpenStoreHandle = errors.New("open store error")

		store, err := NewRemoteProviderStore(storageProvider)

		require.Nil(t, store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open store")
	})

	t.Run("Fail to set store config", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.ErrSetStoreConfig = errors.New("set store config error")

		store, err := NewRemoteProviderStore(storageProvider)

		require.Nil(t, store)
		require.Error(t, err)
		require.Contains(t, err.Error(), "set store config")
	})
}

func TestRemoteProviderStoreImpl_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		record, err := store.Get("id")

		require.NoError(t, err)
		require.Equal(t, "id", record.ID)
		require.Equal(t, "endpoint", record.Endpoint)
	})

	t.Run("Fail to get remote provider from store", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrGet = errors.New("get error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		record, err := store.Get("id")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get remote provider from store")
	})
}

func TestRemoteProviderStoreImpl_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		err = storageProvider.Store.Put("id2", []byte("endpoint2"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		records, err := store.GetAll()

		require.NoError(t, err)
		require.Equal(t, 2, len(records))
	})

	t.Run("Fail to query store for remote provider records", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrQuery = errors.New("query error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		records, err := store.GetAll()

		require.Error(t, err)
		require.Contains(t, err.Error(), "query store")
		require.Equal(t, 0, len(records))
	})

	t.Run("Fail to get next entry while iterating over query set", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrNext = errors.New("next error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		records, err := store.GetAll()

		require.Error(t, err)
		require.Contains(t, err.Error(), "next entry")
		require.Equal(t, 0, len(records))
	})

	t.Run("Fail to get key from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrKey = errors.New("key error")

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		records, err := store.GetAll()

		require.Error(t, err)
		require.Contains(t, err.Error(), "get key")
		require.Equal(t, 0, len(records))
	})

	t.Run("Fail to get value from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		records, err := store.GetAll()

		require.Error(t, err)
		require.Contains(t, err.Error(), "get value")
		require.Equal(t, 0, len(records))
	})
}

func TestRemoteProviderStoreImpl_Save(t *testing.T) {
	t.Run("Save new remote provider record", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		record, err := store.Save("endpoint")

		require.NoError(t, err)
		require.Equal(t, 1, len(storageProvider.Store.Store))
		require.Equal(t, "endpoint", string(storageProvider.Store.Store[record.ID].Value))
	})

	t.Run("Return existing remote provider record", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		record, err := store.Save("endpoint")

		require.NoError(t, err)
		require.Equal(t, 1, len(storageProvider.Store.Store))
		require.Equal(t, "id", record.ID)
		require.Equal(t, "endpoint", record.Endpoint)
	})

	t.Run("Fail to query store for remote provider records", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrQuery = errors.New("query error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		store.debugDisableBackoff = true

		record, err := store.Save("endpoint")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query store")
	})

	t.Run("Fail to get next entry while iterating over query set", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrNext = errors.New("next error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		store.debugDisableBackoff = true

		record, err := store.Save("endpoint")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next entry")
	})

	t.Run("Fail to get key from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrKey = errors.New("key error")

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		store.debugDisableBackoff = true

		record, err := store.Save("endpoint")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get key")
	})

	t.Run("Fail to get value from iterator", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrValue = errors.New("value error")

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		store.debugDisableBackoff = true

		record, err := store.Save("endpoint")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get value")
	})

	t.Run("Fail to save new remote provider record", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrPut = errors.New("put error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		store.debugDisableBackoff = true

		record, err := store.Save("endpoint")

		require.Nil(t, record)
		require.Error(t, err)
		require.Contains(t, err.Error(), "save new remote provider record")
	})
}

func TestRemoteProviderStoreImpl_Delete(t *testing.T) {
	t.Run("Delete remote provider record", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()

		err := storageProvider.Store.Put("id", []byte("endpoint"), storage.Tag{Name: RemoteProviderRecordTag})
		require.NoError(t, err)

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		err = store.Delete("id")

		require.NoError(t, err)
		require.Equal(t, 0, len(storageProvider.Store.Store))
	})

	t.Run("Fail to delete record provider record", func(t *testing.T) {
		storageProvider := mockstorage.NewMockStoreProvider()
		storageProvider.Store.ErrDelete = errors.New("delete error")

		store, err := NewRemoteProviderStore(storageProvider)
		require.NoError(t, err)

		err = store.Delete("id")

		require.Error(t, err)
		require.Contains(t, err.Error(), "delete remote provider record")
	})
}
