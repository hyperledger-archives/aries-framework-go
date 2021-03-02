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

func randomStoreName() string {
	return "store-" + uuid.New().String()
}
