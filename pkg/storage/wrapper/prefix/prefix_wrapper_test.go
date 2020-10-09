// +build !js,!wasm,!ISSUE2183

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prefix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	couchdbstore "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
)

const (
	couchDBURL          = "admin:password@localhost:5981"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/scripts/couchdb-config/10-single-node.ini:/opt/couchdb/etc/local.d/10-single-node.ini"
)

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	path, err := filepath.Abs("./../../../../")
	if err != nil {
		panic(fmt.Sprintf("filepath: %v", err))
	}

	couchdbResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerCouchdbImage,
		Tag:        dockerCouchdbTag,
		Env:        []string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=password"},
		Mounts:     []string{fmt.Sprintf(dockerCouchdbVolume, path)},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5981"}},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(couchdbResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkCouchDB(); err != nil {
		panic(fmt.Sprintf("check CouchDB: %v", err))
	}

	code = m.Run()
}

const retries = 30

func checkCouchDB() error {
	return backoff.Retry(func() error {
		return couchdbstore.PingCouchDB(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func TestCouchDBStore(t *testing.T) {
	cdbPrefix := "t"

	t.Run("Test couchdb store put and get", func(t *testing.T) {
		prov, err := couchdbstore.NewProvider(couchDBURL, couchdbstore.WithDBPrefix("dbprefix"))
		require.NoError(t, err)
		couchdbStore, err := prov.OpenStore(randomKey())
		require.NoError(t, err)

		prefix := "testPrefix"
		store, err := NewPrefixStoreWrapper(couchdbStore, prefix)
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
		require.EqualError(t, err, "cannot Put with empty key")

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

			var store storage.Store

			store, err = NewPrefixStoreWrapper(couchdbStore, cdbPrefix)
			require.NoError(t, err)
			require.NotNil(t, store)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			couchdbStore, e := prov.OpenStore(name)
			require.NoError(t, e)

			var store storage.Store

			store, err = NewPrefixStoreWrapper(couchdbStore, cdbPrefix)
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

	t.Run("Test couchdb store iterator", func(t *testing.T) {
		prov, err := couchdbstore.NewProvider(couchDBURL)
		require.NoError(t, err)
		cdbStore, err := prov.OpenStore(randomKey())
		require.NoError(t, err)

		store, err := NewPrefixStoreWrapper(cdbStore, cdbPrefix)
		require.NoError(t, err)
		require.NotEmpty(t, store)

		const valPrefix = "val-for-%s"
		keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123", "dab_123"}

		for _, key := range keys {
			err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
			require.NoError(t, err)
		}

		itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
		verifyItr(t, itr, 4, cdbPrefix+"abc_")

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
	require.Contains(t, itr.Error().Error(), "Iterator is closed")
}

func TestCouchDBStore_Delete(t *testing.T) {
	const commonKey = "ZGlkOmV4YW1wbGU6MTIzNA" // "did:example:1234" base64 RAW URL encoded

	prov, err := couchdbstore.NewProvider(couchDBURL)
	require.NoError(t, err)

	data := []byte("value1")
	cdbPrefix := "prefix"

	// create store 1 & store 2
	couchdbStore, err := prov.OpenStore(randomKey())
	require.NoError(t, err)

	store1, err := NewPrefixStoreWrapper(couchdbStore, cdbPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, store1)

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
	require.EqualError(t, err, "key is mandatory for deletion")

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
