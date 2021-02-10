// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indexeddb

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

const sampleDBName = "testdb"

func TestCommon(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	commontest.TestPutGet(t, provider)
	commontest.TestStoreDelete(t, provider)
	commontest.TestStoreClose(t, provider)
	commontest.TestProviderClose(t, provider)
}

func TestProviderSetStoreConfig(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	err = provider.SetStoreConfig("storename", storage.StoreConfiguration{})
	require.NoError(t, err)
}

func TestProviderGetStoreConfig(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	_, err = provider.GetStoreConfig("storename")
	require.EqualError(t, err, "not implemented")
}

func TestProviderGetOpenStores(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	stores := provider.GetOpenStores()
	require.Nil(t, stores)
}

func TestStoreGetTags(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	_, err = store.GetTags("key")
	require.EqualError(t, err, "not implemented")
}

func TestStoreGetBulk(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	_, err = store.GetBulk("key")
	require.EqualError(t, err, "not implemented")
}

func TestStoreQuery(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	_, err = store.Query("expression")
	require.EqualError(t, err, "not implemented")
}

func TestStoreFlush(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	err = store.Flush()
	require.NoError(t, err)
}

func TestMultiStore(t *testing.T) {
	t.Run("Test multi store put and get", func(t *testing.T) {
		prov, err := NewProvider(sampleDBName)
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")
		// create store 1 & store 2
		store1, err := prov.OpenStore("store1")
		require.NoError(t, err)

		store2, err := prov.OpenStore("store2")
		require.NoError(t, err)

		// put in store 1
		err = store1.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 1 - found
		doc, err := store1.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// get in store 2 - not found
		doc, err = store2.Get(commonKey)
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Empty(t, doc)

		// put in store 2
		err = store2.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 2 - found
		doc, err = store2.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// create new store 3 with same name as store1
		store3, err := prov.OpenStore("store1")
		require.NoError(t, err)

		// get in store 3 - found
		doc, err = store3.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)
	})
}

func TestStoreBatch(t *testing.T) {
	provider, err := NewProvider(sampleDBName)
	require.NoError(t, err)

	t.Run("Success: put three new values", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []storage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []storage.Tag{{Name: "tagName1"}}},
			{Key: "key2", Value: []byte("value2"), Tags: []storage.Tag{{Name: "tagName2"}}},
			{Key: "key3", Value: []byte("value3"), Tags: []storage.Tag{{Name: "tagName3"}}},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure all values and tags were stored

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1", string(value))

		value, err = store.Get("key2")
		require.NoError(t, err)
		require.Equal(t, "value2", string(value))

		value, err = store.Get("key3")
		require.NoError(t, err)
		require.Equal(t, "value3", string(value))
	})
	t.Run("Success: update three different previously-stored values via Batch", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"), []storage.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []storage.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []storage.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []storage.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: []storage.Tag{{Name: "tagName1"}}},
			{Key: "key2", Value: []byte("value2_new"), Tags: []storage.Tag{{Name: "tagName2_new", Value: "tagValue2"}}},
			{Key: "key3", Value: []byte("value3_new"), Tags: []storage.Tag{{Name: "tagName3_new", Value: "tagValue3_new"}}},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure all values and tags were stored

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1_new", string(value))

		value, err = store.Get("key2")
		require.NoError(t, err)
		require.Equal(t, "value2_new", string(value))

		value, err = store.Get("key3")
		require.NoError(t, err)
		require.Equal(t, "value3_new", string(value))
	})
	t.Run("Success: Delete three different previously-stored values via Batch", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"), []storage.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []storage.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []storage.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []storage.Operation{
			{Key: "key1", Value: nil, Tags: nil},
			{Key: "key2", Value: nil, Tags: nil},
			{Key: "key3", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure values can't be found now

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, storage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		value, err = store.Get("key2")
		require.True(t, errors.Is(err, storage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		value, err = store.Get("key3")
		require.True(t, errors.Is(err, storage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
	})
	t.Run("Success: Put value and then delete it in the same Batch call", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []storage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []storage.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the delete effectively "overrode" the put in the Batch call.

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, storage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
	})
	t.Run("Success: Put value and update it in the same Batch call", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []storage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []storage.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: []byte("value2"), Tags: []storage.Tag{{Name: "tagName2", Value: "tagValue2"}}},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the second put effectively "overrode" the first put in the Batch call.

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value2", string(value))
	})
	t.Run("Failure: Operation has an empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []storage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []storage.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "", Value: []byte("value2"), Tags: []storage.Tag{{Name: "tagName2", Value: "tagValue2"}}},
		}

		err = store.Batch(operations)
		require.Error(t, err)
	})
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
