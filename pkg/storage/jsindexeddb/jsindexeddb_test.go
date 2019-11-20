// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsindexeddb

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestStore(t *testing.T) {
	t.Run("Test store put and get", func(t *testing.T) {
		prov, err := NewProvider()
		require.NoError(t, err)
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
		require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())

		// nil key
		_, err = store.Get("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key is mandatory")

		// nil value
		err = store.Put(key, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key and value are mandatory")

		// nil key
		err = store.Put("", data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key and value are mandatory")

		err = prov.Close()
		require.NoError(t, err)
	})

	t.Run("Test error from open db", func(t *testing.T) {
		dbVersion = 3
		defer func() { dbVersion = 1 }()
		prov, err := NewProvider()
		require.NoError(t, err)
		_, err = prov.OpenStore("test1")
		require.NoError(t, err)
		dbVersion = 2
		_, err = prov.OpenStore("test1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open indexedDB: VersionError")
	})

	t.Run("Test store iterator", func(t *testing.T) {
		prov, err := NewProvider()
		require.NoError(t, err)
		store, err := prov.OpenStore("test3")
		require.NoError(t, err)
		require.Nil(t, store.Iterator("", ""))
	})
}
