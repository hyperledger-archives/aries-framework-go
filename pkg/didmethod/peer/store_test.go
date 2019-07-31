/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/stretchr/testify/require"
)

func setupLevelDB(t testing.TB) (string, func()) {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return dbPath, func() {
		os.RemoveAll(dbPath)
	}
}

func TestPeerDIDStore(t *testing.T) {
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	prov, err := leveldb.NewProvider(path)
	require.NoError(t, err)
	dbstore, err := prov.GetStoreHandle()
	require.NoError(t, err)

	did1 := "did:peer:1234"
	did2 := "did:peer:4567"

	store := NewDIDStore(dbstore)

	// put
	err = store.Put(did1, &did.Doc{ID: did1}, nil)
	require.NoError(t, err)

	// put
	err = store.Put(did2, &did.Doc{ID: did2}, nil)
	require.NoError(t, err)

	// get
	doc, err := store.Get(did1)
	require.NoError(t, err)
	require.Equal(t, did1, doc.ID)

	// get - empty id
	doc, err = store.Get("")
	require.Error(t, err)

	// get - invalid id
	doc, err = store.Get("did:peer:789")
	require.Error(t, err)

	// put - empty id
	err = store.Put("", &did.Doc{ID: did1}, nil)
	require.Error(t, err)

	// put - missing doc
	err = store.Put(did1, nil, nil)
	require.Error(t, err)
}
