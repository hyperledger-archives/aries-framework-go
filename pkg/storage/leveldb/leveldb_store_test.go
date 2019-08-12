/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package leveldb

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestLevelDBStore(t *testing.T) {
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	prov, _ := NewProvider(path)
	store, _ := prov.GetStoreHandle()

	did1 := "did:example:123"
	err := store.Put(did1, []byte("value"))
	require.NoError(t, err)

	doc, err := store.Get(did1)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, []byte("value"), doc)

	did2 := "did:example:789"
	_, err = store.Get(did2)
	require.Error(t, err)

	// nil key
	_, err = store.Get("")
	require.Error(t, err)

	// nil value
	err = store.Put(did1, nil)
	require.Error(t, err)

	// nil key
	err = store.Put("", []byte("value"))
	require.Error(t, err)

	err = prov.Close()
	require.NoError(t, err)

	// try to get after provider is closed
	_, err = store.Get(did1)
	require.Error(t, err)

	// pass file instead of directory for leveldb
	file, err := ioutil.TempFile("", "leveldb.txt")
	if err != nil {
		t.Fatalf("Failed to create leveldb file: %s", err)
	}
	defer cleanupFile(t, file)
	_, err = NewProvider(file.Name())
	require.Error(t, err)
}

func cleanupFile(t *testing.T, file *os.File) {
	err := os.Remove(file.Name())
	if err != nil {
		t.Fatalf("Failed to cleanup file: %s", file.Name())
	}
}
