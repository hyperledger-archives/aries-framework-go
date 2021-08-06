/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package storage contains common tests for storage provider implementations.
// These tests are intended to demonstrate the expected behaviour as defined in the documentation above the
// spi.Provider, spi.Store and spi.Iterator interface declarations.
package storage

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// TestOption is an option for test behaviour.
type TestOption func(opts *testOptions)

type testOptions struct {
	checkIteratorTotalItemCounts bool
}

// WithIteratorTotalItemCountTests makes iterator tests check total item counts.
func WithIteratorTotalItemCountTests() TestOption {
	return func(opts *testOptions) {
		opts.checkIteratorTotalItemCounts = true
	}
}

func getOptions(opts []TestOption) testOptions {
	options := testOptions{}

	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}

	return options
}

// TestAll tests common storage functionality.
// These tests demonstrate behaviour that is expected to be consistent across store implementations.
// The spi.Iterator interface has a TotalItems method, but some implementations may not have it implemented yet.
// For those that do, pass in WithIteratorTotalItemCountTests to enable those tests.
func TestAll(t *testing.T, provider spi.Provider, opts ...TestOption) {
	// Run this first so the store count is predictable.
	t.Run("Provider: GetOpenStores", func(t *testing.T) {
		TestProviderGetOpenStores(t, provider)
	})
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
			TestStoreQuery(t, provider, opts...)
			TestStoreQueryWithSortingAndInitialPageOptions(t, provider, opts...)
		})
		t.Run("Batch", func(t *testing.T) {
			TestStoreBatch(t, provider)
		})
		t.Run("Flush", func(t *testing.T) {
			TestStoreFlush(t, provider)
		})
		t.Run("Close", func(t *testing.T) {
			TestStoreClose(t, provider)
		})
	})
	// Run this last since it may render the provider object unusable afterwards, depending on the implementation.
	t.Run("Provider: close", func(t *testing.T) {
		TestProviderClose(t, provider)
	})
}

// TestProviderOpenStoreSetGetConfig tests common Provider OpenStore, SetStoreConfig, and GetStoreConfig functionality.
func TestProviderOpenStoreSetGetConfig(t *testing.T, provider spi.Provider) { //nolint: funlen // Test file
	t.Run("Set store config with all new tags", func(t *testing.T) {
		testStoreName := randomStoreName()

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		config := spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.NoError(t, err)

		retrievedConfig, err := provider.GetStoreConfig(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, retrievedConfig)
		require.True(t, equalTagNamesAnyOrder(config.TagNames, retrievedConfig.TagNames),
			"Unexpected tag names")
	})
	t.Run("Merge a new tag name in with existing tag names in a store config", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		// Set initial tags.
		err = provider.SetStoreConfig(storeName, spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Get the tags we just set, append a new one, and re-set the store configuration.

		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)

		config.TagNames = append(config.TagNames, "tagName3")

		err = provider.SetStoreConfig(storeName, config)
		require.NoError(t, err)

		// Verify that the config contains all three tags.

		expectedTagNames := []string{"tagName1", "tagName2", "tagName3"}

		retrievedConfig, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.NotNil(t, retrievedConfig)
		require.True(t, equalTagNamesAnyOrder(expectedTagNames, retrievedConfig.TagNames),
			"Unexpected tag names")
	})
	t.Run("Remove all existing tag names in a store config", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		// Set initial tags.
		err = provider.SetStoreConfig(storeName, spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Delete all existing tag names in the config by passing in an empty spi.StoreConfiguration.
		err = provider.SetStoreConfig(storeName, spi.StoreConfiguration{})
		require.NoError(t, err)

		// Verify that the store config now has no tag names.
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.True(t, equalTagNamesAnyOrder(nil, config.TagNames), "Unexpected tag names")
	})
	t.Run("Merge a new tag in with existing tags while deleting some too", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		// Set initial tags.
		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Now we want tagName1 to be removed, tagName2 to be kept, and tagName3 to be added.
		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName2", "tagName3"}})
		require.NoError(t, err)

		expectedTagNames := []string{"tagName2", "tagName3"}

		// Verify that tagName1 was removed, tagName2 was kept, and tagName3 was added.
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.True(t, equalTagNamesAnyOrder(expectedTagNames, config.TagNames), "Unexpected tag names")
	})
	t.Run("Attempt to set config without opening store first", func(t *testing.T) {
		err := provider.SetStoreConfig("NonExistentStore", spi.StoreConfiguration{})
		require.True(t, errors.Is(err, spi.ErrStoreNotFound), "Got unexpected error or no error")
	})
	t.Run("Attempt to set a config that specifies a tag name with a ':' character", func(t *testing.T) {
		testStoreName := randomStoreName()

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		// Tag names cannot contain any ':' characters since it's a reserved character in the query syntax.
		// It would be impossible to do a query for one of these tags, so we must not allow it in the first place.
		config := spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagNameWith:Character"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.Error(t, err)
	})
	t.Run("Attempt to get config without opening store first", func(t *testing.T) {
		config, err := provider.GetStoreConfig("NonExistentStore")
		require.True(t, errors.Is(err, spi.ErrStoreNotFound), "Got unexpected error or no error")
		require.Empty(t, config)
	})
	t.Run("Attempt to open a store with a blank name", func(t *testing.T) {
		store, err := provider.OpenStore("")

		require.Error(t, err)
		require.Nil(t, store)
	})
	t.Run("Demonstrate that store names are not case-sensitive", func(t *testing.T) {
		// Per the interface, store names are not supposed to be case sensitive in order to ensure consistency across
		// storage implementations - some of which don't support case sensitivity in their database names.

		storeWithCapitalLetter, err := provider.OpenStore("Some-store-name")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, storeWithCapitalLetter.Close())
		}()

		err = storeWithCapitalLetter.Put("key", []byte("value"))
		require.NoError(t, err)

		// If the store names are properly case-insensitive, then it's expected that the store below
		// contains the same data as the one above.
		storeWithLowercaseLetter, err := provider.OpenStore("some-store-name")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, storeWithLowercaseLetter.Close())
		}()

		value, err := storeWithLowercaseLetter.Get("key")
		require.NoError(t, err)
		require.Equal(t, "value", string(value))
	})
}

// TestProviderGetOpenStores tests common Provider GetOpenStores functionality.
// This test assumes that the provider passed in has never had stores created under it before.
func TestProviderGetOpenStores(t *testing.T, provider spi.Provider) {
	// No stores have been created yet, so the slice should be empty or nil.
	openStores := provider.GetOpenStores()
	require.Len(t, openStores, 0)

	store1, err := provider.OpenStore("testStore1")
	require.NoError(t, err)

	defer func() {
		// Although we close store1 later on as part of this test, in case it fails early we still need to make
		// sure it's closed. Closing a store multiple times should not cause an error.
		require.NoError(t, store1.Close())
	}()

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 1)

	store2, err := provider.OpenStore("testStore2")
	require.NoError(t, err)

	defer func() {
		// Although we close store2 later on as part of this test, in case it fails early we still need to make
		// sure it's closed. Closing a store multiple times should not cause an error.
		require.NoError(t, store2.Close())
	}()

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 2)

	// Now we will attempt to open a previously opened store. Since it was opened previously, we expect that the
	// number of open stores returned by GetOpenStores() to not change.
	store2Reopened, err := provider.OpenStore("testStore2")
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store2Reopened.Close())
	}()

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 2)

	// Now we will attempt to open a store with the same name as before, but different casing. Since store names are
	// supposed to be case-insensitive, this shouldn't change the number of currently open stores..
	_, err = provider.OpenStore("teststore2")
	require.NoError(t, err)

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 2)

	err = store1.Close()
	require.NoError(t, err)

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 1)

	err = store2.Close()
	require.NoError(t, err)

	openStores = provider.GetOpenStores()
	require.Len(t, openStores, 0)
}

// TestProviderClose tests common Provider Close functionality.
func TestProviderClose(t *testing.T, provider spi.Provider) {
	t.Run("Success", func(t *testing.T) {
		err := provider.Close()
		require.NoError(t, err)
	})
}

// TestPutGet tests common Store Put and Get functionality.
func TestPutGet(t *testing.T, provider spi.Provider) { //nolint: funlen // Test file
	testKeyNonURL := "TestKey"
	testKeyURL := "https://example.com"

	testValueSimpleString := "TestValue"
	testValueSimpleString2 := "TestValue2"
	testValueJSON := `{"someKey1":"someStringValue","someKey2":3,"someKey3":true}`
	testValueJSON2 := `{"someKey1":"someStringValue2","someKey2":3,"someKey3":true}`
	testBinaryData := []byte{0x5f, 0xcb, 0x5c, 0xe9, 0x7f, 0xe3, 0x81}
	testBinaryData2 := []byte{0x5f, 0xcb, 0x5c, 0xe9, 0x7f}

	t.Run("Put and get a value", func(t *testing.T) {
		t.Run("Key is not a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, []byte(testValueSimpleString))
			})
			t.Run("Value is JSON-formatted text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, []byte(testValueJSON))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, testBinaryData)
			})
		})
		t.Run("Key is a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, []byte(testValueSimpleString))
			})
			t.Run("Value is JSON-formatted text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, []byte(testValueJSON))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, testBinaryData)
			})
		})
	})
	t.Run("Put a value, update it, and get the updated value", func(t *testing.T) {
		t.Run("Key is not a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyNonURL,
					[]byte(testValueSimpleString), []byte(testValueSimpleString2))
			})
			t.Run("Value is JSON-formatted text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyNonURL, []byte(testValueJSON), []byte(testValueJSON2))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyNonURL, testBinaryData, testBinaryData2)
			})
		})
		t.Run("Key is a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyURL, []byte(testValueSimpleString),
					[]byte(testValueSimpleString2))
			})
			t.Run("Value is JSON-formatted text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyURL, []byte(testValueJSON), []byte(testValueJSON2))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyURL, testBinaryData, testBinaryData2)
			})
		})
	})
	t.Run("Put a single value, then delete it, then put again using the same key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put(testKeyNonURL, []byte(testValueSimpleString))
		require.NoError(t, err)

		err = store.Delete(testKeyNonURL)
		require.NoError(t, err)

		err = store.Put(testKeyNonURL, []byte("TestValue2"))
		require.NoError(t, err)

		value, err := store.Get(testKeyNonURL)
		require.NoError(t, err)
		require.Equal(t, "TestValue2", string(value))
	})
	t.Run("Tests demonstrating proper store namespacing", func(t *testing.T) {
		t.Run("Put key + value in one store, "+
			"then check that it can't be found in a second store with a different name", func(t *testing.T) {
			store1, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store1.Close())
			}()

			err = store1.Put(testKeyNonURL, []byte(testValueSimpleString))
			require.NoError(t, err)

			store2, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store2.Close())
			}()

			// Store 2 should be disjoint from store 1. It should not contain the key + value pair from store 1.
			value, err := store2.Get(testKeyNonURL)
			require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
			require.Nil(t, value)
		})
		t.Run("Put same key + value in two stores with different names, then update value in one store, "+
			"then check that the other store was not changed",
			func(t *testing.T) {
				store1, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				err = store1.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				store2, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				err = store2.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				// Now both store 1 and 2 contain the same key + value pair.

				newTestValue := testValueSimpleString + "_new"

				// Now update the value in only store 1.
				err = store1.Put(testKeyNonURL, []byte(newTestValue))
				require.NoError(t, err)

				// Store 1 should have the new value.
				value, err := store1.Get(testKeyNonURL)
				require.NoError(t, err)
				require.Equal(t, newTestValue, string(value))

				// Store 2 should still have the old value.
				value, err = store2.Get(testKeyNonURL)
				require.NoError(t, err)
				require.Equal(t, testValueSimpleString, string(value))
			})
		t.Run("Put same key + value in two stores with different names, then delete value in one store, "+
			"then check that the other store still has its key+value pair intact",
			func(t *testing.T) {
				store1, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				err = store1.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				store2, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				err = store2.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				// Now both store 1 and 2 contain the same key + value pair.

				// Now delete the key + value pair in only store 1.
				err = store1.Delete(testKeyNonURL)
				require.NoError(t, err)

				// Store 1 should no longer have the key + value pair.
				value, err := store1.Get(testKeyNonURL)
				require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
				require.Nil(t, value)

				// Store 2 should still have the key + value pair.
				value, err = store2.Get(testKeyNonURL)
				require.NoError(t, err)
				require.Equal(t, testValueSimpleString, string(value))
			})
		t.Run("Put same key + value in two stores with the same name (so they should point to the same "+
			"underlying databases), then update value in one store, then check that the other store also reflects this",
			func(t *testing.T) {
				storeName := randomStoreName()

				store1, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				err = store1.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				// Store 2 should contain the same data as store 1 since they were opened with the same name.
				store2, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				// Store 2 should find the same data that was put in store 1

				valueFromStore1, err := store1.Get(testKeyNonURL)
				require.NoError(t, err)

				valueFromStore2, err := store2.Get(testKeyNonURL)
				require.NoError(t, err)

				require.Equal(t, string(valueFromStore1), string(valueFromStore2))
			})
		t.Run("Put same key + value in two stores with the same name (so they should point to the same "+
			"underlying databases), then delete value in one store, then check that the other store also reflects this",
			func(t *testing.T) {
				storeName := randomStoreName()

				store1, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				err = store1.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				// Store 2 should contain the same data as store 1 since they were opened with the same name.
				store2, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				err = store2.Put(testKeyNonURL, []byte(testValueSimpleString))
				require.NoError(t, err)

				// Now both store 1 and 2 contain the same key + value pair.

				// Now delete the key + value pair in store 1.
				err = store1.Delete(testKeyNonURL)
				require.NoError(t, err)

				// Both store 1 and store 2 should no longer have the key + value pair.
				value, err := store1.Get(testKeyNonURL)
				require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
				require.Nil(t, value)

				value, err = store2.Get(testKeyNonURL)
				require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
				require.Nil(t, value)
			})
	})
	t.Run("Get using empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		_, err = store.Get("")
		require.Error(t, err)
	})
	t.Run("Put with empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("", []byte(testValueSimpleString))
		require.Error(t, err)
	})
	t.Run("Put with vil value", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put(testKeyNonURL, nil)
		require.Error(t, err)
	})
	t.Run("Put with tag containing a ':' character", func(t *testing.T) {
		t.Run("First tag name contains a ':'", func(t *testing.T) {
			store, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = store.Put(testKeyNonURL, []byte("value"),
				[]spi.Tag{
					{Name: "TagName1With:Character", Value: "TagValue1"},
					{Name: "TagName2", Value: "TagValue2"},
				}...)
			require.Error(t, err)
		})
		t.Run("First tag value contains a ':'", func(t *testing.T) {
			store, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = store.Put(testKeyNonURL, []byte("value"),
				[]spi.Tag{
					{Name: "TagName1", Value: "TagValue1With:Character"},
					{Name: "TagName2", Value: "TagValue2"},
				}...)
			require.Error(t, err)
		})
		t.Run("Second tag name contains a ':'", func(t *testing.T) {
			store, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = store.Put(testKeyNonURL, []byte("value"),
				[]spi.Tag{
					{Name: "TagName1", Value: "TagValue1"},
					{Name: "TagName2With:Character", Value: "TagValue2"},
				}...)
			require.Error(t, err)
		})
		t.Run("Second tag value contains a ':'", func(t *testing.T) {
			store, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = store.Put(testKeyNonURL, []byte("value"),
				[]spi.Tag{
					{Name: "TagName1", Value: "TagValue1"},
					{Name: "TagName2", Value: "TagValue2With:Character"},
				}...)
			require.Error(t, err)
		})
	})
}

// TestStoreGetTags tests common Store GetTags functionality.
func TestStoreGetTags(t *testing.T, provider spi.Provider) {
	storeName := randomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	err = provider.SetStoreConfig(storeName,
		spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
	require.NoError(t, err)

	t.Run("Successfully retrieve tags", func(t *testing.T) {
		tags := []spi.Tag{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}}

		key := "key"

		err = store.Put(key, []byte("value1"), tags...)
		require.NoError(t, err)

		receivedTags, err := store.GetTags(key)
		require.NoError(t, err)
		require.True(t, equalTags(tags, receivedTags), "Got unexpected tags")
	})
	t.Run("Data not found", func(t *testing.T) {
		tags, err := store.GetTags("NonExistentKey")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
		require.Empty(t, tags)
	})
	t.Run("Empty key", func(t *testing.T) {
		tags, err := store.GetTags("")
		require.Error(t, err)
		require.Empty(t, tags)
	})
}

// TestStoreGetBulk tests common Store GetBulk functionality.
func TestStoreGetBulk(t *testing.T, provider spi.Provider) { //nolint: funlen // Test file
	t.Run("All values found", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key1", []byte("value1"),
			[]spi.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"),
			[]spi.Tag{
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

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key1", []byte("value1"),
			[]spi.Tag{
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

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key1", []byte("value1"),
			[]spi.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"),
			[]spi.Tag{
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

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key1", []byte("value1"),
			[]spi.Tag{
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

		defer func() {
			require.NoError(t, store.Close())
		}()

		values, err := store.GetBulk(nil...)
		require.Error(t, err)
		require.Nil(t, values)
	})
	t.Run("Empty keys slice", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		values, err := store.GetBulk(make([]string, 0)...)
		require.Error(t, err)
		require.Nil(t, values)
	})
	t.Run("Third key is empty", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		values, err := store.GetBulk("key1", "key2", "")
		require.Error(t, err)
		require.Nil(t, values)
	})
}

// TestStoreDelete tests common Store Delete functionality.
func TestStoreDelete(t *testing.T, provider spi.Provider) {
	t.Run("Delete a stored key", func(t *testing.T) {
		const testKey = "key"

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put(testKey, []byte("value1"))
		require.NoError(t, err)

		err = store.Delete(testKey)
		require.NoError(t, err)

		value, err := store.Get(testKey)
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Empty(t, value)
	})
	t.Run("Delete a key that doesn't exist (not considered an error)", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Delete("NonExistentKey")
		require.NoError(t, err)
	})
	t.Run("Delete with blank key argument", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Delete("")
		require.Error(t, err)
	})
}

// TestStoreQuery tests common Store Query functionality.
func TestStoreQuery(t *testing.T, provider spi.Provider, opts ...TestOption) { // nolint: funlen // Test file
	options := getOptions(opts)

	t.Run("Tag name only query - 2 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		expectedKeys := []string{keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]spi.Tag{tagsToPut[1], tagsToPut[2]}
		expectedTotalItemsCount := 2

		queryExpression := "tagName3"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, spi.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
	})
	t.Run("Tag name only query - 0 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		expectedTotalItemsCount := 0

		queryExpression := "tagName5"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4", "tagName5"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4", "tagName5"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil,
				false, options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4", "tagName5"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, spi.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4", "tagName5"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, nil, nil, nil, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
	})
	t.Run("Tag name and value query - 2 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3", "key4"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3"), []byte("value4")}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}},
		}

		expectedKeys := []string{keysToPut[1], keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[3]}
		expectedTags := [][]spi.Tag{tagsToPut[1], tagsToPut[3]}
		expectedTotalItemsCount := 2

		queryExpression := "tagName3:tagValue1"

		t.Run("Default page setting", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 2", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(2))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 1", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			iterator, err := store.Query(queryExpression, spi.WithPageSize(1))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
		t.Run("Page size 100", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName,
				spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
			require.NoError(t, err)

			putData(t, store, keysToPut, valuesToPut, tagsToPut)

			//nolint:gomnd // Test file
			iterator, err := store.Query(queryExpression, spi.WithPageSize(100))
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
				options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
		})
	})
	t.Run("Tag name and value query - only 1 value found "+
		"(would have been two, but the other was deleted before the query was executed)", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3", "key4"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3"), []byte("value4")}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue1"}},
		}

		expectedKeys := []string{keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[3]}
		expectedTags := [][]spi.Tag{tagsToPut[3]}
		expectedTotalItemsCount := 1

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
		require.NoError(t, err)

		putData(t, store, keysToPut, valuesToPut, tagsToPut)

		err = store.Delete("key2")
		require.NoError(t, err)

		iterator, err := store.Query("tagName3:tagValue1")
		require.NoError(t, err)

		verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, false,
			options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
	})
	t.Run("Tag name and value query - 0 values found since the store is empty", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
		require.NoError(t, err)

		iterator, err := store.Query("tagName3:tagValue1")
		require.NoError(t, err)

		verifyExpectedIterator(t, iterator, nil, nil, nil, false,
			options.checkIteratorTotalItemCounts, 0)
	})
	t.Run("Invalid expression formats", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName, spi.StoreConfiguration{})
		require.NoError(t, err)

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

// TestStoreQueryWithSortingAndInitialPageOptions tests common Store Query functionality when the sorting and initial
// page options are used.
func TestStoreQueryWithSortingAndInitialPageOptions(t *testing.T, //nolint: funlen // Test file
	provider spi.Provider, opts ...TestOption) {
	options := getOptions(opts)

	t.Run("Sorting by a small numerical tag", func(t *testing.T) { //nolint: dupl // Test file
		keysToPutAscendingOrder := []string{
			"key1", "key2", "key3", "key4", "key5", "key6",
			"key7", "key8", "key9", "key10",
		}
		valuesToPutAscendingOrder := [][]byte{
			[]byte("value1"), []byte("value2"), []byte("value3"), []byte("value4"), []byte("value5"), []byte("value6"),
			[]byte("value7"), []byte("value8"), []byte("value9"), []byte("value10"),
		}

		// The tag value associated with "numberTag" will determine the sort order.
		tagsToPutAscendingOrder := [][]spi.Tag{
			{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
				{Name: "numberTag", Value: "1"},
			},
			{
				{Name: "tagName1", Value: "tagValue2"},
				{Name: "tagName2"},
				{Name: "numberTag", Value: "2"},
			},
			{
				{Name: "tagName1", Value: "tagValue3"},
				{Name: "numberTag", Value: "4"},
			},
			{
				{Name: "tagName1", Value: "tagValue4"},
				{Name: "numberTag", Value: "8"},
			},
			{
				{Name: "tagName1", Value: "tagValue5"},
				{Name: "numberTag", Value: "10"},
			},
			{
				{Name: "tagName1", Value: "tagValue6"},
				{Name: "numberTag", Value: "11"},
			},
			{
				{Name: "tagName1", Value: "tagValue7"},
				{Name: "numberTag", Value: "12"},
			},
			{
				{Name: "tagName1", Value: "tagValue8"},
				{Name: "numberTag", Value: "20"},
			},
			{
				{Name: "tagName1", Value: "tagValue9"},
				{Name: "numberTag", Value: "21"},
			},
			{
				{Name: "tagName1", Value: "tagValue10"},
				{Name: "numberTag", Value: "22"},
			},
		}

		storeConfig := spi.StoreConfiguration{TagNames: []string{
			"tagName1", "tagName2", "tagName3", "tagName4",
			"numberTag",
		}}

		queryExpression := "tagName1"

		expectedTotalItemsCount := 10

		t.Run("Data inserted in ascending order", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName, storeConfig)
			require.NoError(t, err)

			putData(t, store, keysToPutAscendingOrder, valuesToPutAscendingOrder, tagsToPutAscendingOrder)

			t.Run("Ascending order", func(t *testing.T) { //nolint: dupl // Test file
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the smallest number to the biggest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[4], keysToPutAscendingOrder[5],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[5],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[5],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page (but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
			t.Run("Descending order", func(t *testing.T) {
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the biggest number to the smallest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						querySortOption := spi.WithSortOrder(&spi.SortOptions{
							Order:   spi.SortDescending,
							TagName: "numberTag",
						})

						iterator, err := store.Query(queryExpression, querySortOption)
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}), spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
		})
		t.Run("Data inserted in arbitrary order", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName, storeConfig)
			require.NoError(t, err)

			keysToPutArbitraryOrder := []string{
				keysToPutAscendingOrder[5], keysToPutAscendingOrder[1], keysToPutAscendingOrder[9],
				keysToPutAscendingOrder[0], keysToPutAscendingOrder[4], keysToPutAscendingOrder[7],
				keysToPutAscendingOrder[2], keysToPutAscendingOrder[8], keysToPutAscendingOrder[6],
				keysToPutAscendingOrder[3],
			}
			valuesToPutArbitraryOrder := [][]byte{
				valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[1], valuesToPutAscendingOrder[9],
				valuesToPutAscendingOrder[0], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[7],
				valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[6],
				valuesToPutAscendingOrder[3],
			}
			tagsToPutArbitraryOrder := [][]spi.Tag{
				tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[1], tagsToPutAscendingOrder[9],
				tagsToPutAscendingOrder[0], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[7],
				tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[6],
				tagsToPutAscendingOrder[3],
			}

			putData(t, store, keysToPutArbitraryOrder, valuesToPutArbitraryOrder, tagsToPutArbitraryOrder)

			t.Run("Ascending order", func(t *testing.T) { //nolint: dupl // Test file
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the smallest number to the biggest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[4], keysToPutAscendingOrder[5],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[5],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[5],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
			t.Run("Descending order", func(t *testing.T) {
				// The results should be sorted numerically (and not lexicographically) on the tag values associated with
				// "numberTag". The order should go from the biggest number to the smallest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						querySortOption := spi.WithSortOrder(&spi.SortOptions{
							Order:   spi.SortDescending,
							TagName: "numberTag",
						})

						iterator, err := store.Query(queryExpression, querySortOption)
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page"+
						"(but there should only be four pages max, so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
		})
	})
	t.Run("Sorting by a large numerical tag (Unix timestamps)", func(t *testing.T) { //nolint: dupl // Test file
		keysToPutAscendingOrder := []string{
			"key1", "key2", "key3", "key4", "key5", "key6",
			"key7", "key8", "key9", "key10",
		}
		valuesToPutAscendingOrder := [][]byte{
			[]byte("value1"), []byte("value2"), []byte("value3"), []byte("value4"), []byte("value5"), []byte("value6"),
			[]byte("value7"), []byte("value8"), []byte("value9"), []byte("value10"),
		}

		// The tag value associated with "numberTag" will determine the sort order.
		tagsToPutAscendingOrder := [][]spi.Tag{
			{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
				{Name: "numberTag", Value: "0"},
			},
			{
				{Name: "tagName1", Value: "tagValue2"},
				{Name: "tagName2"},
				{Name: "numberTag", Value: "1234"},
			},
			{
				{Name: "tagName1", Value: "tagValue3"},
				{Name: "numberTag", Value: "140000"},
			},
			{
				{Name: "tagName1", Value: "tagValue4"},
				{Name: "numberTag", Value: "1000000000"},
			},
			{
				{Name: "tagName1", Value: "tagValue5"},
				{Name: "numberTag", Value: "1619022042"},
			},
			{
				{Name: "tagName1", Value: "tagValue6"},
				{Name: "numberTag", Value: "1619022043"},
			},
			{
				{Name: "tagName1", Value: "tagValue7"},
				{Name: "numberTag", Value: "1619022044"},
			},
			{
				{Name: "tagName1", Value: "tagValue8"},
				{Name: "numberTag", Value: "1619122040"},
			},
			{
				{Name: "tagName1", Value: "tagValue9"},
				{Name: "numberTag", Value: "1619122041"},
			},
			{
				{Name: "tagName1", Value: "tagValue10"},
				{Name: "numberTag", Value: "92147483647"},
			},
		}

		storeConfig := spi.StoreConfiguration{TagNames: []string{
			"tagName1", "tagName2", "tagName3", "tagName4", "numberTag",
		}}

		queryExpression := "tagName1"

		expectedTotalItemsCount := 10

		t.Run("Data inserted in ascending order", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName, storeConfig)
			require.NoError(t, err)

			putData(t, store, keysToPutAscendingOrder, valuesToPutAscendingOrder, tagsToPutAscendingOrder)

			t.Run("Ascending order", func(t *testing.T) { //nolint: dupl // Test file
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the smallest number to the biggest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[4], keysToPutAscendingOrder[5],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[5],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[5],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
			t.Run("Descending order", func(t *testing.T) {
				// The results should be sorted numerically (and not lexicographically) on the tag values associated with
				// "numberTag". The order should go from the biggest number to the smallest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						querySortOption := spi.WithSortOrder(&spi.SortOptions{
							Order:   spi.SortDescending,
							TagName: "numberTag",
						})

						iterator, err := store.Query(queryExpression, querySortOption)
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
		})
		t.Run("Data inserted in arbitrary order", func(t *testing.T) {
			storeName := randomStoreName()

			store, err := provider.OpenStore(storeName)
			require.NoError(t, err)
			require.NotNil(t, store)

			defer func() {
				require.NoError(t, store.Close())
			}()

			err = provider.SetStoreConfig(storeName, storeConfig)
			require.NoError(t, err)

			keysToPutArbitraryOrder := []string{
				keysToPutAscendingOrder[5], keysToPutAscendingOrder[1], keysToPutAscendingOrder[9],
				keysToPutAscendingOrder[0], keysToPutAscendingOrder[4], keysToPutAscendingOrder[7],
				keysToPutAscendingOrder[2], keysToPutAscendingOrder[8], keysToPutAscendingOrder[6],
				keysToPutAscendingOrder[3],
			}
			valuesToPutArbitraryOrder := [][]byte{
				valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[1], valuesToPutAscendingOrder[9],
				valuesToPutAscendingOrder[0], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[7],
				valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[6],
				valuesToPutAscendingOrder[3],
			}
			tagsToPutArbitraryOrder := [][]spi.Tag{
				tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[1], tagsToPutAscendingOrder[9],
				tagsToPutAscendingOrder[0], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[7],
				tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[6],
				tagsToPutAscendingOrder[3],
			}

			putData(t, store, keysToPutArbitraryOrder, valuesToPutArbitraryOrder, tagsToPutArbitraryOrder)

			t.Run("Ascending order", func(t *testing.T) { //nolint: dupl // Test file
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the smallest number to the biggest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := keysToPutAscendingOrder
						expectedValues := valuesToPutAscendingOrder
						expectedTags := tagsToPutAscendingOrder

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[4], keysToPutAscendingOrder[5],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[4], valuesToPutAscendingOrder[5],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[4], tagsToPutAscendingOrder[5],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[7], keysToPutAscendingOrder[8],
							keysToPutAscendingOrder[9],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[7], valuesToPutAscendingOrder[8],
							valuesToPutAscendingOrder[9],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[7], tagsToPutAscendingOrder[8],
							tagsToPutAscendingOrder[9],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortAscending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
			t.Run("Descending order", func(t *testing.T) {
				// The results should be sorted numerically (and not lexicographically) on the tag values associated
				// with "numberTag". The order should go from the biggest number to the smallest.
				t.Run("Default page size setting", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						querySortOption := spi.WithSortOrder(&spi.SortOptions{
							Order:   spi.SortDescending,
							TagName: "numberTag",
						})

						iterator, err := store.Query(queryExpression, querySortOption)
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
				t.Run("Page size 3", func(t *testing.T) {
					t.Run("Start at the default (first) page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at first page (explicitly set)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(0))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[9], keysToPutAscendingOrder[8], keysToPutAscendingOrder[7],
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[9], valuesToPutAscendingOrder[8], valuesToPutAscendingOrder[7],
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[9], tagsToPutAscendingOrder[8], tagsToPutAscendingOrder[7],
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at second page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3), // nolint: gomnd // Test file
							spi.WithInitialPageNum(1))
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[6], keysToPutAscendingOrder[5], keysToPutAscendingOrder[4],
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[6], valuesToPutAscendingOrder[5], valuesToPutAscendingOrder[4],
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[6], tagsToPutAscendingOrder[5], tagsToPutAscendingOrder[4],
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at third page", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(2)) // nolint: gomnd // Test file
						require.NoError(t, err)

						expectedKeys := []string{
							keysToPutAscendingOrder[3], keysToPutAscendingOrder[2], keysToPutAscendingOrder[1],
							keysToPutAscendingOrder[0],
						}
						expectedValues := [][]byte{
							valuesToPutAscendingOrder[3], valuesToPutAscendingOrder[2], valuesToPutAscendingOrder[1],
							valuesToPutAscendingOrder[0],
						}
						expectedTags := [][]spi.Tag{
							tagsToPutAscendingOrder[3], tagsToPutAscendingOrder[2], tagsToPutAscendingOrder[1],
							tagsToPutAscendingOrder[0],
						}

						verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
					t.Run("Start at fifth page(but there should only be four pages max, "+
						"so iterator should have no results)", func(t *testing.T) {
						iterator, err := store.Query(queryExpression,
							spi.WithSortOrder(&spi.SortOptions{
								Order:   spi.SortDescending,
								TagName: "numberTag",
							}),
							spi.WithPageSize(3),       // nolint: gomnd // Test file
							spi.WithInitialPageNum(4)) // nolint: gomnd // Test file
						require.NoError(t, err)

						verifyExpectedIterator(t, iterator, nil, nil, nil, true,
							options.checkIteratorTotalItemCounts, expectedTotalItemsCount)
					})
				})
			})
		})
	})
}

// TestStoreBatch tests common Store Batch functionality.
func TestStoreBatch(t *testing.T, provider spi.Provider) { // nolint:funlen // Test file
	t.Run("Success: put three new values", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		key1TagsToStore := []spi.Tag{{Name: "tagName1"}}
		key2TagsToStore := []spi.Tag{{Name: "tagName2"}}
		key3TagsToStore := []spi.Tag{{Name: "tagName3"}}

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: key1TagsToStore},
			{Key: "key2", Value: []byte("value2"), Tags: key2TagsToStore},
			{Key: "key3", Value: []byte("value3"), Tags: key3TagsToStore},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure all values and tags were stored

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1", string(value))
		retrievedTags, err := store.GetTags("key1")
		require.True(t, equalTags(key1TagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key2")
		require.NoError(t, err)
		require.Equal(t, "value2", string(value))
		retrievedTags, err = store.GetTags("key2")
		require.True(t, equalTags(key2TagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key3")
		require.NoError(t, err)
		require.Equal(t, "value3", string(value))
		retrievedTags, err = store.GetTags("key3")
		require.True(t, equalTags(key3TagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)
	})
	t.Run("Success: update three different previously-stored values", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{
				"tagName1", "tagName2", "tagName3",
				"tagName2_new", "tagName3_new",
			}})
		require.NoError(t, err)

		err = store.Put("key1", []byte("value1"), []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []spi.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []spi.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		key1UpdatedTagsToStore := []spi.Tag{{Name: "tagName1"}}
		key2UpdatedTagsToStore := []spi.Tag{{Name: "tagName2_new", Value: "tagValue2"}}
		key3UpdatedTagsToStore := []spi.Tag{{Name: "tagName3_new", Value: "tagValue3_new"}}

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: key1UpdatedTagsToStore},
			{Key: "key2", Value: []byte("value2_new"), Tags: key2UpdatedTagsToStore},
			{Key: "key3", Value: []byte("value3_new"), Tags: key3UpdatedTagsToStore},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure all values and tags were stored

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1_new", string(value))
		retrievedTags, err := store.GetTags("key1")
		require.True(t, equalTags(key1UpdatedTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key2")
		require.NoError(t, err)
		require.Equal(t, "value2_new", string(value))
		retrievedTags, err = store.GetTags("key2")
		require.True(t, equalTags(key2UpdatedTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key3")
		require.NoError(t, err)
		require.Equal(t, "value3_new", string(value))
		retrievedTags, err = store.GetTags("key3")
		require.True(t, equalTags(key3UpdatedTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)
	})
	t.Run("Success: delete three different previously-stored values", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		err = store.Put("key1", []byte("value1"), []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"), []spi.Tag{{Name: "tagName2", Value: "tagValue2"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []spi.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []spi.Operation{
			{Key: "key1", Value: nil, Tags: nil},
			{Key: "key2", Value: nil, Tags: nil},
			{Key: "key3", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure the values can't be found now

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)

		value, err = store.Get("key2")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err = store.GetTags("key2")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)

		value, err = store.Get("key3")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err = store.GetTags("key3")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)
	})
	t.Run("Success: delete three values, only two of which were previously-stored", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		err = store.Put("key1", []byte("value1"), []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		err = store.Put("key3", []byte("value3"), []spi.Tag{{Name: "tagName3", Value: "tagValue3"}}...)
		require.NoError(t, err)

		operations := []spi.Operation{
			{Key: "key1", Value: nil, Tags: nil},
			{Key: "key2", Value: nil, Tags: nil}, // key2 doesn't exist in the store, but this should not cause an error
			{Key: "key3", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure the values can't be found now

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)

		value, err = store.Get("key3")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err = store.GetTags("key3")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)
	})
	t.Run("Success: put value and then delete it in the same Batch call", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1"}})
		require.NoError(t, err)

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: nil, Tags: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the delete effectively "overrode" the put in the Batch call.

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)
	})
	t.Run("Success: put value and update it in the same Batch call", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		updatedTagsToStore := []spi.Tag{{Name: "tagName2", Value: "tagValue2"}}

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key1", Value: []byte("value2"), Tags: updatedTagsToStore},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the second put operation effectively "overrode" the first operation
		// from the user's perspective.

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value2", string(value))
		retrievedTags, err := store.GetTags("key1")
		require.True(t, equalTags(updatedTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)
	})
	t.Run("Success: update previously-stored value and delete it in the same Batch call", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{
				"tagName1", "tagName2", "tagName3",
				"tagName2_new", "tagName3_new",
			}})
		require.NoError(t, err)

		err = store.Put("key1", []byte("value1"), []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		key1UpdatedTagsToStore := []spi.Tag{{Name: "tagName1"}}

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: key1UpdatedTagsToStore},
			{Key: "key1"},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure the value can't be found now

		value, err := store.Get("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, value)
		tags, err := store.GetTags("key1")
		require.True(t, errors.Is(err, spi.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)
	})
	t.Run("Success: update previously-stored value, then delete it, "+
		"then put it in again using the same key from the first operation, "+
		"all in the same Batch call", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{
				"tagName1", "tagName2", "tagName3",
				"tagName2_new", "tagName3_new",
			}})
		require.NoError(t, err)

		err = store.Put("key1", []byte("value1"), []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}...)
		require.NoError(t, err)

		key1UpdatedTagsToStore := []spi.Tag{{Name: "tagName1"}}
		key1SecondUpdatedTagsToStore := []spi.Tag{{Name: "tagName2"}}

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: key1UpdatedTagsToStore},
			{Key: "key1"},
			{Key: "key1", Value: []byte("value1_new2"), Tags: key1SecondUpdatedTagsToStore},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure that the third operation effectively "overrode" the first two
		// from the user's perspective.

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1_new2", string(value))
		retrievedTags, err := store.GetTags("key1")
		require.True(t, equalTags(key1SecondUpdatedTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)
	})
	t.Run("Success: put values in one batch call, then delete in a second batch call, then put again using "+
		"the same keys that were used in the first batch call in a third batch call", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "key2", Value: []byte("value2"), Tags: []spi.Tag{{Name: "tagName2", Value: "tagValue2"}}},
			{Key: "key3", Value: []byte("value3"), Tags: []spi.Tag{{Name: "tagName3", Value: "tagValue3"}}},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		operations = []spi.Operation{
			{Key: "key1", Value: nil},
			{Key: "key2", Value: nil},
			{Key: "key3", Value: nil},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		key1FinalTagsToStore := []spi.Tag{{Name: "tagName1_new", Value: "tagValue1_new"}}
		key2FinalTagsToStore := []spi.Tag{{Name: "tagName2_new", Value: "tagValue2_new"}}
		key3FinalTagsToStore := []spi.Tag{{Name: "tagName3_new", Value: "tagValue3_new"}}

		operations = []spi.Operation{
			{Key: "key1", Value: []byte("value1_new"), Tags: key1FinalTagsToStore},
			{Key: "key2", Value: []byte("value2_new"), Tags: key2FinalTagsToStore},
			{Key: "key3", Value: []byte("value3_new"), Tags: key3FinalTagsToStore},
		}

		err = store.Batch(operations)
		require.NoError(t, err)

		// Check and make sure the new values were stored

		value, err := store.Get("key1")
		require.NoError(t, err)
		require.Equal(t, "value1_new", string(value))
		retrievedTags, err := store.GetTags("key1")
		require.True(t, equalTags(key1FinalTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key2")
		require.NoError(t, err)
		require.Equal(t, "value2_new", string(value))
		retrievedTags, err = store.GetTags("key2")
		require.True(t, equalTags(key2FinalTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)

		value, err = store.Get("key3")
		require.NoError(t, err)
		require.Equal(t, "value3_new", string(value))
		retrievedTags, err = store.GetTags("key3")
		require.True(t, equalTags(key3FinalTagsToStore, retrievedTags), "Got unexpected tags")
		require.NoError(t, err)
	})
	t.Run("Failure: Operations slice is nil", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Batch(nil)
		require.Error(t, err)
	})
	t.Run("Failure: Operations slice is empty", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Batch([]spi.Operation{})
		require.Error(t, err)
	})
	t.Run("Failure: Operation has an empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		operations := []spi.Operation{
			{Key: "key1", Value: []byte("value1"), Tags: []spi.Tag{{Name: "tagName1", Value: "tagValue1"}}},
			{Key: "", Value: []byte("value2"), Tags: []spi.Tag{{Name: "tagName2", Value: "tagValue2"}}},
		}

		err = store.Batch(operations)
		require.Error(t, err)
	})
}

// TestStoreFlush tests common Store Flush functionality.
func TestStoreFlush(t *testing.T, provider spi.Provider) {
	t.Run("Success", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key1", []byte("value1"))
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"))
		require.NoError(t, err)

		err = store.Flush()
		require.NoError(t, err)

		values, err := store.GetBulk("key1", "key2")
		require.NoError(t, err)
		require.Len(t, values, 2)
		require.Equal(t, "value1", string(values[0]))
		require.Equal(t, "value2", string(values[1]))
	})
}

// TestStoreClose tests common Store Close functionality.
func TestStoreClose(t *testing.T, provider spi.Provider) {
	t.Run("Successfully close store", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.NoError(t, err)
	})
	t.Run("Close same store multiple times without error", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)

		err = store.Close()
		require.NoError(t, err)
	})
}

func doPutThenGetTest(t *testing.T, provider spi.Provider, key string, value []byte) {
	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	err = store.Put(key, value)
	require.NoError(t, err)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)
	require.Equal(t, value, retrievedValue)
}

func doPutThenUpdateThenGetTest(t *testing.T, provider spi.Provider, key string, value, updatedValue []byte) {
	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	err = store.Put(key, value)
	require.NoError(t, err)

	err = store.Put(key, updatedValue)
	require.NoError(t, err)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)
	require.Equal(t, updatedValue, retrievedValue)
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

func putData(t *testing.T, store spi.Store, keys []string, values [][]byte, tags [][]spi.Tag) {
	for i := 0; i < len(keys); i++ {
		err := store.Put(keys[i], values[i], tags[i]...)
		require.NoError(t, err)
	}
}

// expectedKeys, expectedValues, and expectedTags are with respect to the query's page settings.
// Since Iterator.TotalItems' count is not affected by page settings, expectedTotalItemsCount must be passed in and
// can't be determined by looking at the length of expectedKeys, expectedValues, nor expectedTags.
func verifyExpectedIterator(t *testing.T, actualResultsItr spi.Iterator, expectedKeys []string, expectedValues [][]byte,
	expectedTags [][]spi.Tag, orderMatters, checkTotalItemsCount bool, expectedTotalItemsCount int) {
	if len(expectedValues) != len(expectedKeys) || len(expectedTags) != len(expectedKeys) {
		require.FailNow(t,
			"Invalid test case. Expected keys, values and tags slices must be the same length.")
	}

	if orderMatters {
		verifyIteratorInOrder(t, actualResultsItr, expectedKeys, expectedValues, expectedTags, checkTotalItemsCount,
			expectedTotalItemsCount)
	} else {
		verifyIteratorAnyOrder(t, actualResultsItr, expectedKeys, expectedValues, expectedTags, checkTotalItemsCount,
			expectedTotalItemsCount)
	}
}

func verifyIteratorAnyOrder(t *testing.T, actualResultsItr spi.Iterator, //nolint: gocyclo,funlen // Test file
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]spi.Tag,
	checkTotalItemsCount bool, expectedTotalItemsCount int) {
	var dataChecklist struct {
		keys     []string
		values   [][]byte
		tags     [][]spi.Tag
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.tags = expectedTags
	dataChecklist.received = make([]bool, len(expectedKeys))

	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	if !moreResultsToCheck && len(expectedKeys) != 0 {
		require.FailNow(t, "query unexpectedly returned no results")
	}

	for moreResultsToCheck {
		dataReceivedCount := 0

		for _, received := range dataChecklist.received {
			if received {
				dataReceivedCount++
			}
		}

		if dataReceivedCount == len(dataChecklist.received) {
			require.FailNow(t, "iterator contains more results than expected")
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

	if checkTotalItemsCount {
		count, errTotalItems := actualResultsItr.TotalItems()
		require.NoError(t, errTotalItems)
		require.Equal(t, expectedTotalItemsCount, count)
	}

	err = actualResultsItr.Close()
	require.NoError(t, err)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func verifyIteratorInOrder(t *testing.T, actualResultsItr spi.Iterator,
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]spi.Tag,
	checkTotalItemsCount bool, expectedTotalItemsCount int) {
	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	if !moreResultsToCheck && len(expectedKeys) != 0 {
		require.FailNow(t, "query unexpectedly returned no results")
	}

	var currentIndex int

	for moreResultsToCheck {
		var itrErr error
		receivedKey, itrErr := actualResultsItr.Key()
		require.NoError(t, itrErr)
		require.Equal(t, expectedKeys[currentIndex], receivedKey)

		receivedValue, itrErr := actualResultsItr.Value()
		require.NoError(t, itrErr)
		require.Equal(t, string(expectedValues[currentIndex]), string(receivedValue))

		receivedTags, itrErr := actualResultsItr.Tags()
		require.NoError(t, itrErr)
		require.True(t, equalTags(receivedTags, expectedTags[currentIndex]),
			"received unexpected query results")

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)

		if moreResultsToCheck {
			currentIndex++

			if currentIndex+1 > len(expectedKeys) {
				require.FailNow(t, "query returned too many results")
			}
		}
	}

	if checkTotalItemsCount {
		count, errTotalItems := actualResultsItr.TotalItems()
		require.NoError(t, errTotalItems)
		require.Equal(t, expectedTotalItemsCount, count)
	}

	err = actualResultsItr.Close()
	require.NoError(t, err)
}

func equalTags(tags1, tags2 []spi.Tag) bool { //nolint:gocyclo // Test file
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

func equalTagNamesAnyOrder(tagNames1, tagNames2 []string) bool {
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
