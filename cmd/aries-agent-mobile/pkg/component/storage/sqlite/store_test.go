/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sqlite_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/component/storage/sqlite"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/storage"
	basestorage "github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func setupSQLiteDB(t testing.TB) string {
	file, err := ioutil.TempFile("./testdata", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create sqlite file: %s", err)
	}

	dbFolderPath, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatalf("Failed to get absolute path of sqlite directory: %s", err)
	}

	dbPath := filepath.Join(dbFolderPath, filepath.Base(file.Name()))

	t.Cleanup(func() {
		err := file.Close()
		if err != nil {
			t.Fatalf("Failed to close sqlite file: %s", err)
		}
		err = os.Remove(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear sqlite file: %s", err)
		}
	})

	return dbPath
}

func TestSQLDBStore(t *testing.T) {
	t.Run("Test SQL open store", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		_, err = provider.OpenStore("")
		require.Error(t, err)
		require.Equal(t, err.Error(), "store name is required")

		err = provider.Close()
		require.NoError(t, err)
	})
	t.Run("Test sql db store failures", func(t *testing.T) {
		provider, err := sqlite.NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB Path for new SQLite DB provider can't be blank")
		require.Nil(t, provider)

		_, err = sqlite.NewProvider("./testdata/nosqlite.txt")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while pinging SQLite")
	})
	t.Run("Test sqlDB multi store close by name", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path, sqlite.WithDBPrefix("prefixdb"))
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "store_3", "store_5"}

		for _, name := range storeNames {
			store, e := provider.OpenStore(name)
			require.NoError(t, e)

			e = store.Put(commonKey, data, []byte{})
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			store, e := provider.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		for _, name := range storesToClose {
			store, e := provider.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			err = store.Close()
			require.NoError(t, err)
		}

		err = provider.Close()
		require.NoError(t, err)

		// try close all again
		err = provider.Close()
		require.NoError(t, err)
	})
	t.Run("Flush", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		store, err := provider.OpenStore("storename")
		require.NoError(t, err)

		err = store.Flush()
		require.NoError(t, err)

		err = provider.Close()
		require.NoError(t, err)
	})
}

func TestProvider_GetStoreConfig(t *testing.T) {
	t.Run("Fail to get store configuration", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		storeName := randomStoreName()

		_, err = provider.OpenStore(storeName)
		require.NoError(t, err)

		config, err := provider.GetStoreConfig(storeName)
		require.EqualError(t, err,
			fmt.Sprintf(`failed to get store configuration for "%s": `+
				`failed to get DB entry: data not found`, strings.ReplaceAll(storeName, "-", "_")))
		require.Empty(t, config)

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("Fail to update tag map since the DB connection was closed", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		storeName := randomStoreName()
		testStore, err := provider.OpenStore(storeName)
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), []byte{})
		require.EqualError(t, err, fmt.Sprintf("failure while executing insert statement on table %s: "+
			"sql: database is closed", strings.ReplaceAll(storeName, "-", "_")))

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
	t.Run("Fail to unmarshal tag map bytes", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Put("TagMap", []byte("Not a proper tag map"), []byte{})
		require.NoError(t, err)

		tag := basestorage.Tag{}
		tagBytes, err := json.Marshal(tag)
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), tagBytes)
		require.EqualError(t, err, "failed to unmarshal tags: json: "+
			"cannot unmarshal object into Go value of type []storage.Tag")

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
}

func TestSqlDBStore_Query(t *testing.T) {
	t.Run("Fail to get tag map since the DB connection was closed", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		itr, err := testStore.Query("expression", 0)
		require.EqualError(t, err, "failed to get database keys matching query: failed to get tag map: "+
			"failed to get data: failed to get DB entry: failure while querying row: sql: database is closed")
		require.Nil(t, itr)

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
}

func TestSqlDBIterator(t *testing.T) {
	path := setupSQLiteDB(t)

	provider, err := sqlite.NewProvider(path)
	require.NoError(t, err)

	testStoreName := randomStoreName()

	testStore, err := provider.OpenStore(testStoreName)
	require.NoError(t, err)

	storeConfig := basestorage.StoreConfiguration{TagNames: []string{}}
	storeConfigBytes, err := json.Marshal(storeConfig)
	require.NoError(t, err)

	err = provider.SetStoreConfig(testStoreName, storeConfigBytes)
	require.NoError(t, err)

	itr, err := testStore.Query("expression", 0)
	require.NoError(t, err)

	t.Run("Fail to get value from store", func(t *testing.T) {
		value, errValue := itr.Value()
		require.EqualError(t, errValue, "failed to get value from store: failed to get DB entry: key is mandatory")
		require.Nil(t, value)
	})
	t.Run("Fail to get tags from store", func(t *testing.T) {
		tags, errGetTags := itr.Tags()
		require.EqualError(t, errGetTags, "failed to get tags from store: failed to get DB entry: key is mandatory")
		require.Nil(t, tags)
	})

	t.Cleanup(func() {
		err := provider.Close()
		require.NoError(t, err)
	})
}

func TestSqlDBStore_Common(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path)
		require.NoError(t, err)

		wrapperProvider := storage.New(provider)
		commontest.TestProviderOpenStoreSetGetConfig(t, wrapperProvider)
		commontest.TestPutGet(t, wrapperProvider)
		commontest.TestStoreGetTags(t, wrapperProvider)
		commontest.TestStoreQuery(t, wrapperProvider)
		commontest.TestStoreDelete(t, wrapperProvider)
		commontest.TestStoreClose(t, wrapperProvider)
		commontest.TestProviderClose(t, wrapperProvider)
		commontest.TestStoreBatch(t, wrapperProvider)

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
	t.Run("With prefix", func(t *testing.T) {
		path := setupSQLiteDB(t)

		provider, err := sqlite.NewProvider(path, sqlite.WithDBPrefix("dbprefix_"))
		require.NoError(t, err)

		wrapperProvider := storage.New(provider)
		commontest.TestProviderOpenStoreSetGetConfig(t, wrapperProvider)
		commontest.TestPutGet(t, wrapperProvider)
		commontest.TestStoreGetTags(t, wrapperProvider)
		commontest.TestStoreQuery(t, wrapperProvider)
		commontest.TestStoreDelete(t, wrapperProvider)
		commontest.TestStoreClose(t, wrapperProvider)
		commontest.TestProviderClose(t, wrapperProvider)
		commontest.TestStoreBatch(t, wrapperProvider)

		t.Cleanup(func() {
			err := provider.Close()
			require.NoError(t, err)
		})
	})
}

func TestEnsureTagMapIsOnlyCreatedWhenNeeded(t *testing.T) {
	path := setupSQLiteDB(t)

	provider, err := sqlite.NewProvider(path)
	require.NoError(t, err)

	// We defer creating the tag map entry until we actually have to. This saves on space if a client does not need
	// to use tags + querying. The only thing that should cause the tag map entry to be created is if a Put is done
	// with tags.

	testStore, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	storeConfig := basestorage.StoreConfiguration{TagNames: []string{"TagName1"}}
	storeConfigBytes, err := json.Marshal(storeConfig)
	require.NoError(t, err)

	err = provider.SetStoreConfig("TestStore", storeConfigBytes)
	require.NoError(t, err)

	value, err := testStore.Get("TagMap")
	require.True(t, errors.Is(err, basestorage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	err = testStore.Put("Key", []byte("value"), []byte{})
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, basestorage.ErrDataNotFound))
	require.Nil(t, value)

	err = testStore.Delete("Key")
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, basestorage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	tag := []basestorage.Tag{{Name: "TagName1"}}
	tagBytes, err := json.Marshal(tag)
	require.NoError(t, err)

	err = testStore.Put("Key", []byte("value"), tagBytes)
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.NoError(t, err)
	require.Equal(t, `{"TagName1":{"Key":{}}}`, string(value))

	t.Cleanup(func() {
		err = provider.Close()
		require.NoError(t, err)
	})
}

func TestStoreLargeData(t *testing.T) {
	path := setupSQLiteDB(t)
	provider, err := sqlite.NewProvider(path)
	require.NoError(t, err)

	testStore, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	// Store 1 MiB worth of data.
	err = testStore.Put("key", make([]byte, 1000000), []byte{})
	require.NoError(t, err)

	t.Cleanup(func() {
		err = provider.Close()
		require.NoError(t, err)
	})
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
