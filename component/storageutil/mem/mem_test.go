/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestCommon(t *testing.T) {
	provider := mem.NewProvider()

	runCommonTests(t, provider)
}

func TestQueryNotSupportedOptions(t *testing.T) {
	provider := mem.NewProvider()

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	iterator, err := store.Query("TagName:TagValue", spi.WithInitialPageNum(1))
	require.EqualError(t, err, "in-memory provider does not currently support "+
		"setting the initial page number of query results")
	require.Nil(t, iterator)

	iterator, err = store.Query("TagName:TagValue", spi.WithSortOrder(&spi.SortOptions{}))
	require.EqualError(t, err, "in-memory provider does not currently support custom sort options "+
		"for query results")
	require.Nil(t, iterator)
}

func TestMemIterator(t *testing.T) {
	provider := mem.NewProvider()

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	iterator, err := store.Query("TagName1;TagValue2")
	require.NoError(t, err)

	key, err := iterator.Key()
	require.EqualError(t, err, "iterator is exhausted")
	require.Empty(t, key)

	value, err := iterator.Value()
	require.EqualError(t, err, "iterator is exhausted")
	require.Nil(t, value)

	tags, err := iterator.Tags()
	require.EqualError(t, err, "iterator is exhausted")
	require.Nil(t, tags)
}

func runCommonTests(t *testing.T, provider spi.Provider) {
	storagetest.TestProviderGetOpenStores(t, provider)
	storagetest.TestProviderOpenStoreSetGetConfig(t, provider)
	storagetest.TestPutGet(t, provider)
	storagetest.TestStoreGetTags(t, provider)
	storagetest.TestStoreGetBulk(t, provider)
	storagetest.TestStoreDelete(t, provider)
	storagetest.TestStoreQuery(t, provider)
	storagetest.TestStoreBatch(t, provider)
	storagetest.TestStoreFlush(t, provider)
	storagetest.TestStoreClose(t, provider)
	storagetest.TestProviderClose(t, provider)
}
