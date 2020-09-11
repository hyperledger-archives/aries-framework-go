// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package base58wrapper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/go-kivik/kivik"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	couchdbstore "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
)

const (
	couchDBURL = "admin:password@localhost:5984"
)

// For these unit tests to run, you must ensure you have a CouchDB instance running at the URL specified in couchDBURL.
// 'make unit-test' from the terminal will take care of this for you.
// To run the tests manually, start an instance by running docker run -p 5984:5984 couchdb:2.3.1 from a terminal.

func TestMain(m *testing.M) {
	err := checkCouchDB()
	if err != nil {
		fmt.Printf(err.Error() +
			". Make sure you start a couchDB instance using" +
			" 'docker run -p 5984:5984 couchdb:2.3.1' before running the unit tests")
		os.Exit(0)
	}

	os.Exit(m.Run())
}

func checkCouchDB() error {
	client, err := kivik.New("couch", couchDBURL)
	if err != nil {
		return err
	}

	_, err = client.Ping(context.Background())

	return err
}

func TestCouchDBStore(t *testing.T) {
	t.Run("Test couchdb store put and get", func(t *testing.T) {
		prov, err := couchdbstore.NewProvider(couchDBURL, couchdbstore.WithDBPrefix("dbprefix"))
		require.NoError(t, err)
		couchdbStore, err := prov.OpenStore(randomKey())
		require.NoError(t, err)

		store := NewBase58StoreWrapper(couchdbStore)

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
		require.Error(t, err)

		err = prov.Close()
		require.NoError(t, err)
	})

	t.Run("Test couchdb multi store close by name", func(t *testing.T) {
		prov, err := couchdbstore.NewProvider(couchDBURL, couchdbstore.WithDBPrefix("dbprefix"))
		require.NoError(t, err)

		const commonKey = "ZGlkOmV4YW1wbGU6MQ" // "did:example:1" base64 RAW URL encoded

		data := []byte("value1")

		storeNames := []string{randomKey(), randomKey(), randomKey(), randomKey(), randomKey()}
		storesToClose := []string{storeNames[0], storeNames[2], storeNames[4]}

		for _, name := range storeNames {
			couchdbStore, e := prov.OpenStore(name)
			require.NoError(t, e)

			store := NewBase58StoreWrapper(couchdbStore)
			require.NotNil(t, store)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			couchdbStore, e := prov.OpenStore(name)
			require.NoError(t, e)

			store := NewBase58StoreWrapper(couchdbStore)
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

			e = prov.CloseStore(name)
			require.NoError(t, e)
		}

		// verify store length
		// require.Len(t, prov.dbs, 2) // not available in the wrapper provider

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.NoError(t, err)

		// verify store length
		// require.Len(t, prov.dbs, 2) // not available in the wrapper provider

		err = prov.Close()
		require.NoError(t, err)

		// verify store length
		// require.Empty(t, prov.dbs) // not available in the wrapper provider

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
}

func TestCouchDBStore_Delete(t *testing.T) {
	const commonKey = "ZGlkOmV4YW1wbGU6MTIzNA" // "did:example:1234" base64 RAW URL encoded

	prov, err := couchdbstore.NewProvider(couchDBURL)
	require.NoError(t, err)

	data := []byte("value1")

	// create store 1 & store 2
	couchdbStore, err := prov.OpenStore(randomKey())
	require.NoError(t, err)

	store1 := NewBase58StoreWrapper(couchdbStore)

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

func randomKey() string {
	// prefix `key` is needed for couchdb due to error e.g Name: '7c80bdcd-b0e3-405a-bb82-fae75f9f2470'.
	// Only lowercase characters (a-z), digits (0-9), and any of the characters _, $, (, ), +, -, and / are allowed.
	// Must begin with a letter.
	return "key" + uuid.New().String()
}
