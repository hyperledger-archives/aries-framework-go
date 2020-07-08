/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestPeerDIDStore(t *testing.T) {
	_, err := New(&storage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf("open store failed")})
	require.Error(t, err)
	require.Contains(t, err.Error(), "open store failed")

	prov := storage.NewMockStoreProvider()
	dbstore, err := prov.OpenStore(StoreNamespace)
	require.NoError(t, err)

	context := []string{"https://w3id.org/did/v1"}

	did1 := "did:peer:1234"
	did2 := "did:peer:4567"

	store, err := New(prov)
	require.NoError(t, err)
	// put
	err = store.Store(&did.Doc{Context: context, ID: did1}, nil)
	require.NoError(t, err)

	// put
	err = store.Store(&did.Doc{Context: context, ID: did2}, nil)
	require.NoError(t, err)

	// get
	doc, err := store.Get(did1)
	require.NoError(t, err)
	require.Equal(t, did1, doc.ID)

	// get - empty id
	_, err = store.Get("")
	require.Error(t, err)

	// get - invalid id
	_, err = store.Get("did:peer:789")
	require.Error(t, err)

	// put - empty id
	err = store.Store(&did.Doc{ID: ""}, nil)
	require.Error(t, err)

	// put - missing doc
	err = store.Store(nil, nil)
	require.Error(t, err)

	// get - not json document
	err = dbstore.Put("not-json", []byte("not json"))
	require.NoError(t, err)
	v, err := store.Get("not-json")
	require.NotNil(t, err)
	require.Nil(t, v)
	require.Contains(t, err.Error(), "delta data fetch from store")

	t.Run("returns vdri.ErrNotFound if did is not resolved", func(t *testing.T) {
		store, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)

		_, err = store.Get("nonexistent")
		require.Error(t, err)
		require.True(t, errors.Is(err, vdriapi.ErrNotFound))
	})
}

func TestVDRI_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New(&storage.MockStoreProvider{})
		require.NoError(t, err)
		require.NoError(t, v.Close())
	})
}
