// +build !ISSUE2183

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

type Provider struct {
	storage.Provider
	Name string
}

func TestStore(t *testing.T) {
	providers := setUpProviders(t)

	for i := range providers {
		provider := providers[i]

		t.Run("Store put and get "+provider.Name, func(t *testing.T) {
			t.Parallel()

			store, err := provider.OpenStore(randomKey())
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
		})

		t.Run("Multi store put and get "+provider.Name, func(t *testing.T) {
			t.Parallel()

			const commonKey = "did:example:1"
			data := []byte("value1")
			// create store 1 & store 2
			store1name := randomKey()
			store1, err := provider.OpenStore(store1name)
			require.NoError(t, err)

			store2, err := provider.OpenStore(randomKey())
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
			store3, err := provider.OpenStore(store1name)
			require.NoError(t, err)

			// get in store 3 - found
			doc, err = store3.Get(commonKey)
			require.NoError(t, err)
			require.NotEmpty(t, doc)
			require.Equal(t, data, doc)
		})

		t.Run("Iterator "+provider.Name, func(t *testing.T) {
			t.Parallel()

			store, err := provider.OpenStore(randomKey())
			require.NoError(t, err)

			const valPrefix = "val-for-%s"
			keys := []string{
				"abc_123", "abc_124",
				"abc_125", "abc_126", "jkl_123", "mno_123", "dab_123",
				"route_connID_1", "route_connID_2", "route_grant_1", "route_grant_2",
			}

			for _, key := range keys {
				err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
				require.NoError(t, err)
			}

			itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
			verifyItr(t, itr, 4, "abc_")

			itr = store.Iterator("route_connID_", "route_connID_"+storage.EndKeySuffix)
			verifyItr(t, itr, 2, "route_connID_")

			itr = store.Iterator("", "dab_123")
			verifyItr(t, itr, 4, "")

			itr = store.Iterator("abc_124", "")
			verifyItr(t, itr, 0, "")

			itr = store.Iterator("", "")
			verifyItr(t, itr, 0, "")

			itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
			verifyItr(t, itr, 7, "")

			itr = store.Iterator("abc_", "mno_123")
			verifyItr(t, itr, 6, "")

			itr = store.Iterator("t_", "t_"+storage.EndKeySuffix)
			verifyItr(t, itr, 0, "")
		})

		t.Run("Delete "+provider.Name, func(t *testing.T) {
			t.Parallel()

			const commonKey = "did:example:1234"

			data := []byte("value1")

			// create store 1 & store 2
			store, err := provider.OpenStore(randomKey())
			require.NoError(t, err)

			// put in store 1
			err = store.Put(commonKey, data)
			require.NoError(t, err)

			// get in store 1 - found
			doc, err := store.Get(commonKey)
			require.NoError(t, err)
			require.NotEmpty(t, doc)
			require.Equal(t, data, doc)

			// now try Delete with an empty key - should fail
			err = store.Delete("")
			require.EqualError(t, err, "key is mandatory")

			err = store.Delete("k1")
			require.NoError(t, err)

			// finally test Delete an existing key
			err = store.Delete(commonKey)
			require.NoError(t, err)

			doc, err = store.Get(commonKey)
			require.EqualError(t, err, storage.ErrDataNotFound.Error())
			require.Empty(t, doc)
		})
	}
}

func verifyItr(t *testing.T, itr storage.StoreIterator, count int, prefix string) {
	t.Helper()

	var values []string

	for itr.Next() {
		if prefix != "" {
			require.True(t, strings.HasPrefix(string(itr.Key()), prefix))
		}

		values = append(values, string(itr.Value()))
	}
	require.Len(t, values, count)

	itr.Release()
	require.False(t, itr.Next())
	require.Empty(t, itr.Key())
	require.Empty(t, itr.Value())
	require.Error(t, itr.Error())
}

func randomKey() string {
	// prefix `key` is needed for couchdb due to error e.g Name: '7c80bdcd-b0e3-405a-bb82-fae75f9f2470'.
	// Only lowercase characters (a-z), digits (0-9), and any of the characters _, $, (, ), +, -, and / are allowed.
	// Must begin with a letter.
	return "key" + uuid.New().String()
}
