/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func setupLevelDB(t testing.TB) (string, func()) {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	return dbPath, func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}

func TestLeveldbStore(t *testing.T) {
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	t.Run("Test Leveldb store put and get", func(t *testing.T) {
		prov := NewProvider(path)
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

		// test update
		data = []byte(`{"key1":"value1"}`)
		err = store.Put(key, data)
		require.NoError(t, err)

		doc, err = store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// test update
		update := []byte(`{"_key1":"value1"}`)
		err = store.Put(key, update)
		require.NoError(t, err)

		doc, err = store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, update, doc)

		did2 := "did:example:789"
		_, err = store.Get(did2)
		require.True(t, errors.Is(err, storage.ErrDataNotFound))

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

	t.Run("Test Leveldb multi store put and get", func(t *testing.T) {
		prov := NewProvider(path)
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

	t.Run("Test Leveldb store failures", func(t *testing.T) {
		// pass file instead of directory for leveldb
		file, err := ioutil.TempFile("", "leveldb.txt*-sample")
		if err != nil {
			t.Fatalf("Failed to create leveldb file: %s", err)
		}
		defer cleanupFile(t, file)

		prov := NewProvider(strings.Split(file.Name(), "-")[0])
		store, err := prov.OpenStore("sample")
		require.Error(t, err)
		require.Nil(t, store)
	})

	t.Run("Test Leveldb multi store close by name", func(t *testing.T) {
		prov := NewProvider(path)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "store_3", "store_5"}

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

	t.Run("Test Leveldb store iterator", func(t *testing.T) {
		prov := NewProvider(path)
		store, err := prov.OpenStore("test-iterator")
		require.NoError(t, err)

		const valPrefix = "val-for-%s"
		keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

		for _, key := range keys {
			err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
			require.NoError(t, err)
		}

		itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
		verifyItr(t, itr, 4, "abc_")

		itr = store.Iterator("", "")
		verifyItr(t, itr, 0, "")

		itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
		verifyItr(t, itr, 7, "")

		itr = store.Iterator("abc_", "mno_123")
		verifyItr(t, itr, 6, "")
	})
}

func verifyItr(t *testing.T, itr storage.StoreIterator, count int, prefix string) {
	t.Helper()

	var vals []string

	for itr.Next() {
		if prefix != "" {
			require.True(t, strings.HasPrefix(string(itr.Key()), prefix))
		}

		vals = append(vals, string(itr.Value()))
	}
	require.Len(t, vals, count)

	itr.Release()
	require.False(t, itr.Next())
	require.Empty(t, itr.Key())
	require.Empty(t, itr.Value())
	require.Error(t, itr.Error())
	require.Contains(t, itr.Error().Error(), "iterator released")
}

func cleanupFile(t *testing.T, file *os.File) {
	err := os.Remove(file.Name())
	if err != nil {
		t.Fatalf("Failed to cleanup file: %s", file.Name())
	}
}

func TestLeveldbStore_Delete(t *testing.T) {
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	const commonKey = "did:example:1234"

	prov := NewProvider(path)
	data := []byte("value1")

	// create store 1 & store 2
	store1, err := prov.OpenStore("store1")
	require.NoError(t, err)

	// put in store 1
	err = store1.Put(commonKey, data)
	require.NoError(t, err)

	// get in store 1 - found
	doc, err := store1.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// now try Delete with an empty key - should fail
	err = store1.Delete("")
	require.EqualError(t, err, "key is mandatory")

	err = store1.Delete("k1")
	require.NoError(t, err)

	// finally test Delete an existing key
	err = store1.Delete(commonKey)
	require.NoError(t, err)

	doc, err = store1.Get(commonKey)
	require.EqualError(t, err, storage.ErrDataNotFound.Error())
	require.Empty(t, doc)
}
