/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func setupLevelDB(t testing.TB) string {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	t.Cleanup(func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	})

	return dbPath
}

func TestCommon(t *testing.T) {
	path := setupLevelDB(t)

	provider := leveldb.NewProvider(path)

	commontest.TestAll(t, provider, commontest.SkipSortTests(false))
}

func TestProvider_GetStoreConfig(t *testing.T) {
	t.Run("Fail to get store configuration", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		storeName := randomStoreName()

		_, err := provider.OpenStore(storeName)
		require.NoError(t, err)

		config, err := provider.GetStoreConfig(storeName)
		require.EqualError(t, err,
			fmt.Sprintf(`failed to get store configuration for "%s": `+
				`failed to get DB entry: data not found`, storeName))
		require.Empty(t, config)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("Fail to update tag map since the DB connection was closed", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), storage.Tag{})
		require.EqualError(t, err, "failed to update tag map: failed to get tag map: "+
			"failed to get tag map: failed to get DB entry: leveldb: closed")
	})
	t.Run("Fail to unmarshal tag map bytes", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Put("TagMap", []byte("Not a proper tag map"))
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), storage.Tag{})
		require.EqualError(t, err, "failed to update tag map: failed to get tag map: "+
			"failed to unmarshal tag map bytes: invalid character 'N' looking for beginning of value")
	})
}

func TestStore_Query(t *testing.T) {
	t.Run("Fail to get tag map since the DB connection was closed", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		itr, err := testStore.Query("expression")
		require.EqualError(t, err, "failed to get database keys matching query: failed to get tag map: "+
			"failed to get tag map: failed to get DB entry: leveldb: closed")
		require.Nil(t, itr)
	})
	t.Run("Not supported options", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue", storage.WithInitialPageNum(1))
		require.EqualError(t, err, "levelDB provider does not currently support "+
			"setting the initial page number of query results")
		require.Nil(t, iterator)

		iterator, err = store.Query("TagName:TagValue", storage.WithSortOrder(&storage.SortOptions{}))
		require.EqualError(t, err, "levelDB provider does not currently support custom sort options "+
			"for query results")
		require.Nil(t, iterator)
	})
}

func TestStore_Flush(t *testing.T) {
	path := setupLevelDB(t)

	provider := leveldb.NewProvider(path)

	store, err := provider.OpenStore("storename")
	require.NoError(t, err)

	err = store.Flush()
	require.NoError(t, err)
}

func TestIterator(t *testing.T) {
	path := setupLevelDB(t)

	provider := leveldb.NewProvider(path)

	testStore, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	itr, err := testStore.Query("expression")
	require.NoError(t, err)

	t.Run("Fail to get value from store", func(t *testing.T) {
		value, errValue := itr.Value()
		require.EqualError(t, errValue, "failed to get value from store: failed to get DB entry: "+
			"key cannot be blank")
		require.Nil(t, value)
	})
	t.Run("Fail to get tags from store", func(t *testing.T) {
		tags, errGetTags := itr.Tags()
		require.EqualError(t, errGetTags, "failed to get tags from store: failed to get DB entry: "+
			"key cannot be blank")
		require.Nil(t, tags)
	})
}

func TestEnsureTagMapIsOnlyCreatedWhenNeeded(t *testing.T) {
	path := setupLevelDB(t)

	provider := leveldb.NewProvider(path)

	// We defer creating the tag map entry until we actually have to. This saves on space if a client does not need
	// to use tags + querying. The only thing that should cause the tag map entry to be created is if a Put is done
	// with tags.

	testStore, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	err = provider.SetStoreConfig("TestStore", storage.StoreConfiguration{TagNames: []string{"TagName1"}})
	require.NoError(t, err)

	value, err := testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	err = testStore.Put("Key", []byte("value"))
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound))
	require.Nil(t, value)

	err = testStore.Delete("Key")
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	err = testStore.Put("Key", []byte("value"), storage.Tag{Name: "TagName1"})
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.NoError(t, err)
	require.Equal(t, `{"TagName1":{"Key":{}}}`, string(value))
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
