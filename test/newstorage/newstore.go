/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package newstorage contains common tests for storage provider implementations.
package newstorage

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
)

// TestAll tests common storage functionality.
// These tests demonstrate behaviour that is expected to be consistent across store implementations.
func TestAll(t *testing.T, provider newstorage.Provider) {
	t.Run("Provider: open store and set/get config", func(t *testing.T) {
		TestProviderOpenStoreSetGetConfig(t, provider)
	})
	t.Run("Store", func(t *testing.T) {
		t.Run("Put and Get", func(t *testing.T) {
			TestPutGet(t, provider)
		})
		t.Run("GetTags", func(t *testing.T) {
			TestStoreGetTags(t, provider)
		})
		t.Run("GetBulk", func(t *testing.T) {
			TestStoreGetBulk(t, provider)
		})
		t.Run("Delete", func(t *testing.T) {
			TestStoreDelete(t, provider)
		})
		t.Run("Query", func(t *testing.T) {
			TestStoreQuery(t, provider)
		})
		t.Run("Batch", func(t *testing.T) {
			TestStoreBatch(t, provider)
		})
		t.Run("Close", func(t *testing.T) {
			TestStoreClose(t, provider)
		})
	})
	t.Run("Provider: close", func(t *testing.T) { // Run this last since it'll end up destroying the provider
		TestProviderClose(t, provider)
	})
}

// TestProviderOpenStoreSetGetConfig tests common Provider OpenStore, SetStoreConfig, and GetStoreConfig functionality.
func TestProviderOpenStoreSetGetConfig(t *testing.T, provider newstorage.Provider) {
	config := newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}}

	testStoreName := randomStoreName()

	t.Run("Successfully open store, set store config and then get store config", func(t *testing.T) {
		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig(testStoreName, config)
		require.NoError(t, err)

		retrievedConfig, err := provider.GetStoreConfig(testStoreName)
		require.NoError(t, err)
		require.True(t, equalTagNamesAnyOrder(config.TagNames, retrievedConfig.TagNames),
			"Unexpected tag names")
	})
	t.Run("Attempt to set config without opening store first", func(t *testing.T) {
		err := provider.SetStoreConfig("NonExistentStore", config)
		require.True(t, errors.Is(err, newstorage.ErrStoreNotFound), "Got unexpected error or no error")
	})
	t.Run("Attempt to get config without opening store first", func(t *testing.T) {
		config, err := provider.GetStoreConfig("NonExistentStore")
		require.True(t, errors.Is(err, newstorage.ErrStoreNotFound), "Got unexpected error or no error")
		require.Empty(t, config)
	})
}

// TestProviderClose tests common Provider Close functionality.
func TestProviderClose(t *testing.T, provider newstorage.Provider) {
	t.Run("Success", func(t *testing.T) {
		err := provider.Close()
		require.NoError(t, err)
	})
}

// TestPutGet tests common Store Put and Get functionality.
func TestPutGet(t *testing.T, provider newstorage.Provider) { //nolint: funlen // Test file
	store1Name := randomStoreName()

	store1, errOpen := provider.OpenStore(store1Name)
	require.NoError(t, errOpen)

	key := "did:example:1"

	data := []byte("value1")

	t.Run("Put and get value with multiple stores", func(t *testing.T) {
		store2Name := randomStoreName()

		store2, err := provider.OpenStore(store2Name)
		require.NoError(t, err)

		// Put in store 1.
		err = store1.Put(key, data)
		require.NoError(t, err)

		// Try getting from store 1 - should be found.
		doc, err := store1.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// Try getting from store 2 - should not be found
		doc, err = store2.Get(key)
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "Got unexpected error or no error")
		require.Nil(t, doc)

		// Put in store 2.
		err = store2.Put(key, data)
		require.NoError(t, err)

		// Now we should be able to get that value from store 2.
		doc, err = store2.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// Create store 3 with the same name as store 1.
		store3, err := provider.OpenStore(store1Name)
		require.NoError(t, err)
		require.NotNil(t, store3)

		// Since store 3 points to the same underlying database as store 1, the data should be found.
		doc, err = store3.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)
	})
	t.Run("Get using empty key", func(t *testing.T) {
		_, err := store1.Get("")
		require.Error(t, err)
	})
	t.Run("Put with empty key", func(t *testing.T) {
		err := store1.Put("", data)
		require.Error(t, err)
	})
	t.Run("Put with vil value", func(t *testing.T) {
		err := store1.Put(key, nil)
		require.Error(t, err)
	})
}

// TestStoreGetTags tests common Store GetTags functionality.
func TestStoreGetTags(t *testing.T, provider newstorage.Provider) {
	storeName := randomStoreName()
	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	t.Run("Successfully retrieve tags", func(t *testing.T) {
		tags := []newstorage.Tag{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}}

		key := "did:example:1"

		err = store.Put(key, []byte("value1"), tags...)
		require.NoError(t, err)

		receivedTags, err := store.GetTags(key)
		require.NoError(t, err)
		require.True(t, equalTags(tags, receivedTags), "Got unexpected tags")
	})
	t.Run("Data not found", func(t *testing.T) {
		tags, err := store.GetTags("NonExistentKey")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "Got unexpected error or no error")
		require.Empty(t, tags)
	})
	t.Run("Empty key", func(t *testing.T) {
		tags, err := store.GetTags("")
		require.Error(t, err)
		require.Empty(t, tags)
	})
}

// TestStoreGetBulk tests common Store GetBulk functionality.
func TestStoreGetBulk(t *testing.T, provider newstorage.Provider) { //nolint: funlen // Test file
	t.Run("All values found", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		values, err := store.GetBulk("key1", "key2")
		require.NoError(t, err)
		require.Len(t, values, 2)
		require.Equal(t, "value1", string(values[0]))
		require.Equal(t, "value2", string(values[1]))
	})
	t.Run("One value found, one not", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		values, err := store.GetBulk("key1", "key2")
		require.NoError(t, err)
		require.Len(t, values, 2)
		require.Equal(t, "value1", string(values[0]))
		require.Nil(t, values[1])
	})
	t.Run("One value found, one not because it was deleted", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		err = store.Delete("key2")
		require.NoError(t, err)

		values, err := store.GetBulk("key1", "key2")
		require.NoError(t, err)
		require.Len(t, values, 2)
		require.Equal(t, "value1", string(values[0]))
		require.Nil(t, values[1])
	})
	t.Run("No values found", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		values, err := store.GetBulk("key3", "key4")
		require.NoError(t, err)
		require.Len(t, values, 2)
		require.Nil(t, values[0])
		require.Nil(t, values[1])
	})
	t.Run("Nil keys slice", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		values, err := store.GetBulk(nil...)
		require.Error(t, err)
		require.Nil(t, values)
	})
	t.Run("Empty keys slice", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		values, err := store.GetBulk(make([]string, 0)...)
		require.Error(t, err)
		require.Nil(t, values)
	})
	t.Run("Blank key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		values, err := store.GetBulk("key1", "key2", "")
		require.Error(t, err)
		require.Nil(t, values)
	})
}

// TestStoreDelete tests common Store Delete functionality.
func TestStoreDelete(t *testing.T, provider newstorage.Provider) {
	const commonKey = "did:example:1234"

	data := []byte("value1")

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	// Put in store 1
	err = store.Put(commonKey, data)
	require.NoError(t, err)

	// Try getting from store 1 - should be found.
	doc, err := store.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// Delete an existing key - should succeed.
	err = store.Delete(commonKey)
	require.NoError(t, err)

	// Delete a key which never existed. Should not throw any error.
	err = store.Delete("k1")
	require.NoError(t, err)

	// Try to get the value stored under the deleted key - should fail.
	doc, err = store.Get(commonKey)
	require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
	require.Empty(t, doc)

	// Try Delete with an empty key - should fail.
	err = store.Delete("")
	require.Error(t, err)
}

// TestStoreQuery tests common Store Query functionality.
func TestStoreQuery(t *testing.T, provider newstorage.Provider) { // nolint: funlen // Test file
	t.Run("Tag name only query - 2 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}
		tagsToPut := [][]newstorage.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		expectedKeys := []string{keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]newstorage.Tag{tagsToPut[1], tagsToPut[2]}

		queryExpression := "tagName3"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
	})
	t.Run("Tag name only query - 0 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}
		tagsToPut := [][]newstorage.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		queryExpression := "nonExistentTagName"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(" ")
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil)
		})
	})
	t.Run("Tag name and value query - 2 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3", "key4"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3"), []byte("value4")}
		tagsToPut := [][]newstorage.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}},
		}

		expectedKeys := []string{keysToPut[1], keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[3]}
		expectedTags := [][]newstorage.Tag{tagsToPut[1], tagsToPut[3]}

		queryExpression := "tagName3:tagValue1"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			err = provider.SetStoreConfig(storeName,
				newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, newstorage.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags)
		})
	})
	t.Run("Invalid expression formats", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		t.Run("Empty expression", func(t *testing.T) {
			iterator, err := store.Query("")
			require.Error(t, err)
			require.Empty(t, iterator)
		})
		t.Run("Too many colon-separated parts", func(t *testing.T) {
			iterator, err := store.Query("name:value:somethingElse")
			require.Error(t, err)
			require.Empty(t, iterator)
		})
	})
}

// TestStoreBatch tests common Store Batch functionality.
func TestStoreBatch(t *testing.T, provider newstorage.Provider) { // nolint:funlen // Test file
	t.Run("Success: put three new values", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []newstorage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []newstorage.Tag{{Name: "tagName1"}}},
			{Key: "key2", Value: []byte("value2"), Tags: []newstorage.Tag{{Name: "tagName2"}}},
			{Key: "key3", Value: []byte("value3"), Tags: []newstorage.Tag{{Name: "tagName3"}}},
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

		tags, err := store.GetTags("key1")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName1", tags[0].Name)

		tags, err = store.GetTags("key2")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName2", tags[0].Name)

		tags, err = store.GetTags("key3")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName3", tags[0].Name)
	})
	t.Run("Success: update three different previously-stored values via Batch", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"), []newstorage.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []newstorage.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []newstorage.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []newstorage.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: []newstorage.Tag{{Name: "tagName1"}}},
			{Key: "key2", Value: []byte("value2_new"), Tags: []newstorage.Tag{{Name: "tagName2_new", Value: "tagValue2"}}},
			{Key: "key3", Value: []byte("value3_new"), Tags: []newstorage.Tag{{Name: "tagName3_new", Value: "tagValue3_new"}}},
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

		tags, err := store.GetTags("key1")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName1", tags[0].Name)
		require.Equal(t, "", tags[0].Value)

		tags, err = store.GetTags("key2")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName2_new", tags[0].Name)
		require.Equal(t, "tagValue2", tags[0].Value)

		tags, err = store.GetTags("key3")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName3_new", tags[0].Name)
		require.Equal(t, "tagValue3_new", tags[0].Value)
	})
	t.Run("Success: Delete three different previously-stored values via Batch", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key1", []byte("value1"), []newstorage.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []newstorage.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []newstorage.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []newstorage.Operation{
			{Key: "key1", Value: nil, Tags: nil},
			{Key: "key2", Value: nil, Tags: nil},
			{Key: "key3", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure values can't be found now

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		value, err = store.Get("key2")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		value, err = store.Get("key3")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Empty(t, tags)

		tags, err = store.GetTags("key2")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Empty(t, tags)

		tags, err = store.GetTags("key3")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Empty(t, tags)
	})
	t.Run("Success: Put value and then delete it in the same Batch call", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []newstorage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []newstorage.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the delete effectively "overrode" the put in the Batch call.

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)

		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Empty(t, tags)
	})
	t.Run("Success: Put value and update it in the same Batch call", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		operations := []newstorage.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []newstorage.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: []byte("value2"), Tags: []newstorage.Tag{{Name: "tagName2", Value: "tagValue2"}}},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the second put effectively "overrode" the first put in the Batch call.

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value2", string(value))

		tags, err := store.GetTags("key1")
		require.NoError(t, err)
		require.Len(t, tags, 1)
		require.Equal(t, "tagName2", tags[0].Name)
		require.Equal(t, "tagValue2", tags[0].Value)
	})
}

// TestStoreClose tests common Store Close functionality.
func TestStoreClose(t *testing.T, provider newstorage.Provider) {
	t.Run("Successfully close store", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.NoError(t, err)
	})
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

func putData(t *testing.T, store newstorage.Store, keys []string, values [][]byte, tags [][]newstorage.Tag) {
	for i := 0; i < len(keys); i++ {
		err := store.Put(keys[i], values[i], tags[i]...)
		require.NoError(t, err)
	}
}

func verifyExpectedIterator(t *testing.T, // nolint:gocyclo,funlen // Test file
	actualResultsItr newstorage.Iterator,
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]newstorage.Tag) {
	if len(expectedValues) != len(expectedKeys) || len(expectedTags) != len(expectedKeys) {
		require.FailNow(t,
			"Invalid test case. Expected keys, values and tags slices must be the same length.")
	}

	var dataChecklist struct {
		keys     []string
		values   [][]byte
		tags     [][]newstorage.Tag
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.tags = expectedTags
	dataChecklist.received = make([]bool, len(expectedKeys))

	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	for moreResultsToCheck {
		dataReceivedCount := 0

		for _, received := range dataChecklist.received {
			if received {
				dataReceivedCount++
			}
		}

		if dataReceivedCount == len(dataChecklist.received) {
			require.FailNow(t, "query returned more results than expected")
		}

		var itrErr error
		receivedKey, itrErr := actualResultsItr.Key()
		require.NoError(t, itrErr)

		receivedValue, itrErr := actualResultsItr.Value()
		require.NoError(t, itrErr)

		receivedTags, itrErr := actualResultsItr.Tags()
		require.NoError(t, itrErr)

		for i := 0; i < len(dataChecklist.keys); i++ {
			if receivedKey == dataChecklist.keys[i] {
				if string(receivedValue) == string(dataChecklist.values[i]) {
					if equalTags(receivedTags, dataChecklist.tags[i]) {
						dataChecklist.received[i] = true

						break
					}
				}
			}
		}

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)
	}

	err = actualResultsItr.Close()
	require.NoError(t, err)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func equalTags(tags1, tags2 []newstorage.Tag) bool { //nolint:gocyclo // Test file
	if len(tags1) != len(tags2) {
		return false
	}

	matchedTags1 := make([]bool, len(tags1))
	matchedTags2 := make([]bool, len(tags2))

	for i, tag1 := range tags1 {
		for j, tag2 := range tags2 {
			if matchedTags2[j] {
				continue // This tag has already found a match. Tags can only have one match!
			}

			if tag1.Name == tag2.Name && tag1.Value == tag2.Value {
				matchedTags1[i] = true
				matchedTags2[j] = true

				break
			}
		}

		if !matchedTags1[i] {
			return false
		}
	}

	for _, matchedTag := range matchedTags1 {
		if !matchedTag {
			return false
		}
	}

	for _, matchedTag := range matchedTags2 {
		if !matchedTag {
			return false
		}
	}

	return true
}

func equalTagNamesAnyOrder(tagNames1, tagNames2 []string) bool { //nolint: gocyclo // Test file
	if len(tagNames1) != len(tagNames2) {
		return false
	}

	areTagNamesMatchedFromSlice1 := make([]bool, len(tagNames1))
	areTagNamesMatchedFromSlice2 := make([]bool, len(tagNames2))

	for i, tagName1 := range tagNames1 {
		for j, tagName2 := range tagNames2 {
			if areTagNamesMatchedFromSlice2[j] {
				continue // This tag name has already found a match. Tag names can only have one match!
			}

			if tagName1 == tagName2 {
				areTagNamesMatchedFromSlice1[i] = true
				areTagNamesMatchedFromSlice2[j] = true

				break
			}
		}

		if !areTagNamesMatchedFromSlice1[i] {
			return false
		}
	}

	for _, isTagNameMatch := range areTagNamesMatchedFromSlice1 {
		if !isTagNameMatch {
			return false
		}
	}

	for _, isTagNameMatch := range areTagNamesMatchedFromSlice2 {
		if !isTagNameMatch {
			return false
		}
	}

	return true
}
