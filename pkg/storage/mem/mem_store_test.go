/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestMemStore(t *testing.T) {
	t.Run("Test mem store put and get", func(t *testing.T) {
		prov := NewProvider()
		store, err := prov.OpenStore("test")
		require.NoError(t, err)

		const key = "did:example:123"
		data := []byte("value")

		err = store.Put(key, data)
		require.NoError(t, err)

		doc, err := store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		did2 := "did:example:789"
		_, err = store.Get(did2)
		require.Error(t, err)

		// nil key
		_, err = store.Get("")
		require.Error(t, err)

		// nil value
		err = store.Put(key, nil)
		require.Error(t, err)

		// nil key
		err = store.Put("", data)
		require.Error(t, err)

		err = prov.Close()
		require.NoError(t, err)

		// try to get after provider is closed
		_, err = store.Get(key)
		require.Error(t, err)
	})

	t.Run("Test mem multi store put and get", func(t *testing.T) {
		prov := NewProvider()
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

		// store length
		require.Len(t, prov.dbs, 2)
	})

	t.Run("Test mem multi store close by name", func(t *testing.T) {
		prov := NewProvider()
		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "STore_3", "stOre_5"}

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		// verify store length
		require.Len(t, prov.dbs, 5)

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			e = prov.CloseStore(name)
			require.NoError(t, e)

			dataRead, e := store.Get(commonKey)
			require.Error(t, e)
			require.Empty(t, dataRead)
		}

		// verify store length
		require.Len(t, prov.dbs, 2)

		// try to close non existing db
		err := prov.CloseStore("store_x")
		require.NoError(t, err)

		// verify store length
		require.Len(t, prov.dbs, 2)

		err = prov.Close()
		require.NoError(t, err)

		// verify store length
		require.Empty(t, prov.dbs)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
}

func TestMemStoreIterator(t *testing.T) {
	t.Run("Test mem store iterator", func(t *testing.T) {
		prov := NewProvider()
		store, err := prov.OpenStore("test")
		require.NoError(t, err)

		rawData := make(map[string][]byte)
		rawData["key1"] = []byte("value1")
		rawData["key2"] = []byte("value2")
		rawData["key3"] = []byte("value3")

		for k, v := range rawData {
			err = store.Put(k, v)
			require.NoError(t, err)
		}

		itr := store.Iterator("", "")
		defer itr.Release()

		count := 0
		for itr.Next() {
			val := rawData[string(itr.Key())]
			require.Equal(t, val, itr.Value())
			count++
		}
		require.Equal(t, len(rawData), count)
	})

	t.Run("Test mem store iterator - no data in iterator", func(t *testing.T) {
		// no data from iterator
		prov := NewProvider()
		store, err := prov.OpenStore("test2")
		require.NoError(t, err)

		itr := store.Iterator("", "")
		defer itr.Release()

		require.False(t, itr.Next())
		require.Nil(t, itr.Key())
		require.Nil(t, itr.Value())
		require.NoError(t, itr.Error())
	})
}
