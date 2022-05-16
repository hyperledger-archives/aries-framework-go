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

	storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
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

func TestProvider_Ping(t *testing.T) {
	provider := mem.NewProvider()

	err := provider.Ping()
	require.NoError(t, err)
}

func TestMemStore_Query(t *testing.T) {
	provider := mem.NewProvider()

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	const (
		tagName1 = "TagName1"
		tagName2 = "TagName2"
		tagName3 = "TagName3"

		tagValue1 = "TagValue1"
		tagValue2 = "TagValue2"

		key1 = "key1"
		key2 = "key2"
		key3 = "key3"
		key4 = "key4"

		value1 = "value1"
		value2 = "value2"
		value3 = "value3"
		value4 = "value4"
	)

	require.NoError(t, store.Put(key1, []byte(value1),
		spi.Tag{Name: tagName1, Value: tagValue1},
		spi.Tag{Name: tagName2, Value: tagValue2},
		spi.Tag{Name: tagName3}),
	)

	require.NoError(t, store.Put(key2, []byte(value2),
		spi.Tag{Name: tagName1, Value: tagValue1},
		spi.Tag{Name: tagName2, Value: tagValue2}),
	)

	require.NoError(t, store.Put(key3, []byte(value3),
		spi.Tag{Name: tagName1, Value: tagValue1}),
	)

	require.NoError(t, store.Put(key4, []byte(value4),
		spi.Tag{Name: tagName1, Value: "xxx"},
		spi.Tag{Name: tagName3}),
	)

	t.Run("All tags -> one result", func(t *testing.T) {
		iterator, err := store.Query("TagName1:TagValue1&&TagName2:TagValue2&&TagName3")
		require.NoError(t, err)

		ok, err := iterator.Next()
		require.NoError(t, err)
		require.True(t, ok)

		key, err := iterator.Key()
		require.NoError(t, err)
		require.Equal(t, key1, key)

		value, err := iterator.Value()
		require.NoError(t, err)
		require.Equal(t, value1, string(value))

		ok, err = iterator.Next()
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("Tag2 -> 2 results", func(t *testing.T) {
		iterator, err := store.Query("TagName2:TagValue2")
		require.NoError(t, err)

		ok, err := iterator.Next()
		require.NoError(t, err)
		require.True(t, ok)

		key, err := iterator.Key()
		require.NoError(t, err)
		require.True(t, containsKey(key, key1, key2))

		ok, err = iterator.Next()
		require.NoError(t, err)
		require.True(t, ok)

		key, err = iterator.Key()
		require.NoError(t, err)
		require.True(t, containsKey(key, key1, key2))

		ok, err = iterator.Next()
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("Tag3 -> 2 results", func(t *testing.T) {
		iterator, err := store.Query("TagName3")
		require.NoError(t, err)

		ok, err := iterator.Next()
		require.NoError(t, err)
		require.True(t, ok)

		key, err := iterator.Key()
		require.NoError(t, err)
		require.True(t, containsKey(key, key1, key4))

		ok, err = iterator.Next()
		require.NoError(t, err)
		require.True(t, ok)

		key, err = iterator.Key()
		require.NoError(t, err)
		require.True(t, containsKey(key, key1, key4))

		ok, err = iterator.Next()
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("Invalid value for tag -> no results", func(t *testing.T) {
		iterator, err := store.Query("TagName1:TagValueX")
		require.NoError(t, err)

		ok, err := iterator.Next()
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func containsKey(key string, expectedKey ...string) bool {
	for _, k := range expectedKey {
		if k == key {
			return true
		}
	}

	return false
}
