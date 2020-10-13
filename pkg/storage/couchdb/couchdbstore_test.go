// +build !js,!wasm,!ISSUE2183

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kivik/kivik"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/log/mocklogger"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	couchDBURL          = "admin:password@localhost:5982"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/scripts/couchdb-config/10-single-node.ini:/opt/couchdb/etc/local.d/10-single-node.ini"
)

var mockLoggerProvider = mocklogger.Provider{MockLogger: &mocklogger.MockLogger{}} //nolint: gochecknoglobals

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	path, err := filepath.Abs("./../../../")
	if err != nil {
		panic(fmt.Sprintf("filepath: %v", err))
	}

	couchdbResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerCouchdbImage,
		Tag:        dockerCouchdbTag,
		Env:        []string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=password"},
		Mounts:     []string{fmt.Sprintf(dockerCouchdbVolume, path)},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5982"}},
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

	log.Initialize(&mockLoggerProvider)

	code = m.Run()
}

const retries = 30

func checkCouchDB() error {
	return backoff.Retry(func() error {
		return PingCouchDB(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func TestCouchDBStore(t *testing.T) {
	t.Run("Couchdb connection refused", func(t *testing.T) {
		const (
			driverName     = "couch"
			dataSourceName = "admin:password@localhost:1111"
			dbName         = "db_name"
		)

		client, err := kivik.New(driverName, dataSourceName)
		require.NoError(t, err)

		db := &CouchDBStore{db: client.DB(context.Background(), dbName)}
		require.Error(t, db.Put("key", []byte("val")))
	})

	t.Run("Test couchdb store put and get", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL, WithDBPrefix("dbprefix"))
		require.NoError(t, err)
		store, err := prov.OpenStore(randomKey())
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
	})

	t.Run("Test couchdb multi store put and get", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL)
		require.NoError(t, err)
		const commonKey = "did:example:1"
		data := []byte("value1")
		// create store 1 & store 2
		store1name := randomKey()
		store1, err := prov.OpenStore(store1name)
		require.NoError(t, err)

		store2, err := prov.OpenStore(randomKey())
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
		store3, err := prov.OpenStore(store1name)
		require.NoError(t, err)

		// get in store 3 - found
		doc, err = store3.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// store length
		require.Len(t, prov.dbs, 2)
	})

	t.Run("Test couchdb store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), blankHostErrMsg)
		require.Nil(t, prov)

		_, err = NewProvider("wrongURL")
		require.Error(t, err)
	})

	t.Run("Test couchdb multi store close by name", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL, WithDBPrefix("dbprefix"))
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{randomKey(), randomKey(), randomKey(), randomKey(), randomKey()}
		storesToClose := []string{storeNames[0], storeNames[2], storeNames[4]}

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
		}

		// verify store length
		require.Len(t, prov.dbs, 2)

		// try to close non existing db
		err = prov.CloseStore("store_x")
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

	t.Run("Test couchdb store iterator", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL)
		require.NoError(t, err)
		store, err := prov.OpenStore(randomKey())
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

	t.Run("Test CouchDB store query", func(t *testing.T) {
		t.Run("Successfully query using index", func(t *testing.T) {
			queryTest(t, "payload.employeeID")
		})
		t.Run("Successful query, but the specified index isn't valid for the query", func(t *testing.T) {
			// Despite the selected index ("name") not being applicable to our query ("payload.employeeID"),
			// CouchDB doesn't throw an error. Instead, it just ignores the chosen index and still does the search,
			// albeit slowly. When this happens, we log the warning message returned from CouchDB.
			queryTest(t, "name")

			require.Contains(t, mockLoggerProvider.MockLogger.WarnLogContents,
				`_design/TestDesignDoc, TestIndex was not used because it is not a valid index for this query.
No matching index found, create an index to optimize query time.`)
		})
		t.Run("Fail to query - invalid query JSON", func(t *testing.T) {
			prov, err := NewProvider(couchDBURL)
			require.NoError(t, err)
			store, err := prov.OpenStore(randomKey())
			require.NoError(t, err)

			itr, err := store.Query(``)
			require.EqualError(t,
				err, "failed to query CouchDB using the find endpoint: Bad Request: invalid UTF-8 JSON")
			require.Nil(t, itr)
		})
	})
}

func queryTest(t *testing.T, fieldToIndex string) {
	prov, err := NewProvider(couchDBURL)
	require.NoError(t, err)
	store, err := prov.OpenStore(randomKey())
	require.NoError(t, err)

	couchDBStore, ok := store.(*CouchDBStore)
	require.True(t, ok, "failed to assert store as a CouchDBStore")

	testJSONPayload := []byte(`{"employeeID":1234,"name":"Mr. Aries"}`)

	err = store.Put("sampleDBKey", testJSONPayload)
	require.NoError(t, err)

	const designDocName = "TestDesignDoc"

	const indexName = "TestIndex"

	err = couchDBStore.db.CreateIndex(context.Background(), designDocName, indexName,
		`{"fields": ["`+fieldToIndex+`"]}`)
	require.NoError(t, err)

	itr, err := store.Query(`{
		   "selector": {
		       "payload.employeeID": 1234
		   },
			"use_index": ["` + designDocName + `", "` + indexName + `"]
		}`)
	require.NoError(t, err)

	ok = itr.Next()
	require.True(t, ok)
	require.NoError(t, itr.Error())

	value := itr.Value()
	require.Equal(t, testJSONPayload, value)
	require.NoError(t, itr.Error())

	ok = itr.Next()
	require.False(t, ok)
	require.NoError(t, itr.Error())

	itr.Release()
	require.NoError(t, itr.Error())
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
	const commonKey = "did:example:1234"

	prov, err := NewProvider(couchDBURL)
	require.NoError(t, err)

	data := []byte("value1")

	// create store 1 & store 2
	store1, err := prov.OpenStore(randomKey())
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

func randomKey() string {
	// prefix `key` is needed for couchdb due to error e.g Name: '7c80bdcd-b0e3-405a-bb82-fae75f9f2470'.
	// Only lowercase characters (a-z), digits (0-9), and any of the characters _, $, (, ), +, -, and / are allowed.
	// Must begin with a letter.
	return "key" + uuid.New().String()
}
