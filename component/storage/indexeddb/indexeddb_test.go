// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indexeddb_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/indexeddb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

const sampleDBName = "testdb"

func TestCommon(t *testing.T) {
	provider, err := indexeddb.NewProvider(sampleDBName)
	require.NoError(t, err)

	commontest.TestPutGet(t, provider)
	commontest.TestStoreGetTags(t, provider)
	commontest.TestProviderOpenStoreSetGetConfig(t, provider)
	commontest.TestStoreDelete(t, provider)
	commontest.TestStoreQuery(t, provider)
	commontest.TestStoreBatch(t, provider)
	commontest.TestStoreClose(t, provider)
	commontest.TestProviderClose(t, provider)
}

func TestProviderGetOpenStores(t *testing.T) {
	provider, err := indexeddb.NewProvider(sampleDBName)
	require.NoError(t, err)

	stores := provider.GetOpenStores()
	require.Nil(t, stores)
}

func TestStoreGetBulk(t *testing.T) {
	provider, err := indexeddb.NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	_, err = store.GetBulk("key")
	require.EqualError(t, err, "not implemented")
}

func TestStoreFlush(t *testing.T) {
	provider, err := indexeddb.NewProvider(sampleDBName)
	require.NoError(t, err)

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	err = store.Flush()
	require.NoError(t, err)
}

func TestMultiStore(t *testing.T) {
	t.Run("Test multi store put and get", func(t *testing.T) {
		prov, err := indexeddb.NewProvider(sampleDBName)
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

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
