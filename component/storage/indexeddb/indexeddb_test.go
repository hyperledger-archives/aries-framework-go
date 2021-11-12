// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indexeddb_test

import (
	"errors"
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

func TestEnsureTagMapIsOnlyCreatedWhenNeeded(t *testing.T) {
	provider, err := indexeddb.NewProvider(sampleDBName)
	require.NoError(t, err)

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
