// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prefix

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestStorePrefixWrapper(t *testing.T) {
	_, errNewPrefixStoreWrapper := NewPrefixStoreWrapper(nil, "")
	require.EqualError(t, errNewPrefixStoreWrapper, "newPrefixStoreWrapper: prefix is empty")

	cdbPrefix := "t"

	t.Run("Test put and get", func(t *testing.T) {
		prov := mem.NewProvider()
		memStore, err := prov.OpenStore(uuid.New().String())
		require.NoError(t, err)

		var store storage.Store

		store, err = NewPrefixStoreWrapper(memStore, "testPrefix")
		require.NoError(t, err)

		const key = "ZGlkOmV4YW1wbGU6MTIz" // "did:example:123" base64 RAW URL encoded
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

		did2 := "ZGlkOmV4YW1wbGU6Nzg5" // "did:example:789" base64 RAW URL encoded
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
		require.EqualError(t, err, "key cannot be empty")

		err = prov.Close()
		require.NoError(t, err)
	})

	t.Run("Test multi store close by name", func(t *testing.T) {
		prov := mem.NewProvider()

		const commonKey = "ZGlkOmV4YW1wbGU6MQ" // "did:example:1" base64 RAW URL encoded

		data := []byte("value1")

		storeNames := []string{
			uuid.New().String(), uuid.New().String(),
			uuid.New().String(), uuid.New().String(),
			uuid.New().String(),
		}
		storesToClose := []string{storeNames[0], storeNames[2], storeNames[4]}

		for _, name := range storeNames {
			memStore, e := prov.OpenStore(name)
			require.NoError(t, e)

			var store storage.Store

			store, err := NewPrefixStoreWrapper(memStore, cdbPrefix)
			require.NoError(t, err)
			require.NotNil(t, store)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			memStore, e := prov.OpenStore(name)
			require.NoError(t, e)

			var store storage.Store

			store, err := NewPrefixStoreWrapper(memStore, cdbPrefix)
			require.NoError(t, err)
			require.NotNil(t, store)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		// verify store length
		// require.Len(t, prov.dbs, 5) // not available in the wrapper provider

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)
		}

		// verify store length
		// require.Len(t, prov.dbs, 2) // not available in the wrapper provider

		// verify store length
		// require.Len(t, prov.dbs, 2) // not available in the wrapper provider

		err := prov.Close()
		require.NoError(t, err)

		// verify store length
		// require.Empty(t, prov.dbs) // not available in the wrapper provider

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
}

func TestStorePrefixWrapper_Delete(t *testing.T) {
	const commonKey = "ZGlkOmV4YW1wbGU6MTIzNA" // "did:example:1234" base64 RAW URL encoded

	prov := mem.NewProvider()

	data := []byte("value1")

	// create store 1 & store 2
	memStore, err := prov.OpenStore(uuid.New().String())
	require.NoError(t, err)

	var store storage.Store

	store, err = NewPrefixStoreWrapper(memStore, "prefix")
	require.NoError(t, err)
	require.NotEmpty(t, store)

	// put in store
	err = store.Put(commonKey, data)
	require.NoError(t, err)

	// get in store - found
	doc, err := store.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// now try Delete with an empty key - should fail
	err = store.Delete("")
	require.EqualError(t, err, "key cannot be empty")

	err = store.Delete("k1")
	require.NoError(t, err)

	// finally test Delete an existing key
	err = store.Delete(commonKey)
	require.NoError(t, err)

	doc, err = store.Get(commonKey)
	require.EqualError(t, err, storage.ErrDataNotFound.Error())
	require.Empty(t, doc)
}
