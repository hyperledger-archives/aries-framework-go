/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb_test

import (
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

	commontest.TestProviderOpenStoreSetGetConfig(t, provider)
	commontest.TestPutGet(t, provider)
	commontest.TestStoreGetTags(t, provider)
	commontest.TestStoreQuery(t, provider)
	commontest.TestStoreDelete(t, provider)
	commontest.TestStoreClose(t, provider)
	commontest.TestProviderClose(t, provider)
}

func TestNotImplementedMethods(t *testing.T) {
	t.Run("Not implemented methods", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		require.Panics(t, func() {
			provider.GetOpenStores()
		})

		store, err := provider.OpenStore("storename")
		require.NoError(t, err)

		_, err = store.GetBulk()
		require.EqualError(t, err, "not implemented")

		err = store.Batch(nil)
		require.EqualError(t, err, "not implemented")
	})
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
		require.EqualError(t, err, "failed to get tag map: failed to get tag map: failed to get DB entry: "+
			"leveldb: closed")
		require.Nil(t, itr)
	})
	t.Run("Fail to unmarshal tag map bytes", func(t *testing.T) {
		path := setupLevelDB(t)

		provider := leveldb.NewProvider(path)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Put("TagMap", []byte("Not a proper tag map"))
		require.NoError(t, err)

		itr, err := testStore.Query("expression")
		require.EqualError(t, err, "failed to get tag map: failed to unmarshal tag map bytes: "+
			"invalid character 'N' looking for beginning of value")
		require.Nil(t, itr)
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

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
