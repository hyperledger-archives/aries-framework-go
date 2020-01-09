/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/internal/mock/diddoc"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

type ctx struct {
	store storage.Provider
	vdr   vdriapi.Registry
}

func (c *ctx) StorageProvider() storage.Provider {
	return c.store
}

func (c *ctx) VDRIRegistry() vdriapi.Registry {
	return c.vdr
}

func TestBaseConnectionStore(t *testing.T) {
	prov := ctx{
		store: mockstorage.NewMockStoreProvider(),
		vdr: &mockvdri.MockVDRIRegistry{
			CreateValue:  mockdiddoc.GetMockDIDDoc(),
			ResolveValue: mockdiddoc.GetMockDIDDoc(),
		},
	}

	t.Run("New", func(t *testing.T) {
		_, err := New(&prov)
		require.NoError(t, err)

		_, err = New(&ctx{
			store: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("store error"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
	})

	t.Run("SaveDID error", func(t *testing.T) {
		cs, err := New(&ctx{
			store: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store:  map[string][]byte{},
					ErrPut: fmt.Errorf("put error"),
				},
			},
			vdr: &mockvdri.MockVDRIRegistry{
				CreateValue:  mockdiddoc.GetMockDIDDoc(),
				ResolveValue: mockdiddoc.GetMockDIDDoc(),
			},
		})
		require.NoError(t, err)

		err = cs.SaveDID("did", "key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})

	t.Run("SaveDID + GetDID", func(t *testing.T) {
		connStore, err := New(&prov)
		require.NoError(t, err)

		err = connStore.SaveDID("did:abcde", "abcde")
		require.NoError(t, err)

		didVal, err := connStore.GetDID("abcde")
		require.NoError(t, err)
		require.Equal(t, "did:abcde", didVal)

		wrong, err := connStore.GetDID("fhtagn")
		require.EqualError(t, err, ErrNotFound.Error())
		require.Equal(t, "", wrong)

		err = connStore.store.Put("bad-data", []byte("aaooga"))
		require.NoError(t, err)

		_, err = connStore.GetDID("bad-data")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("SaveDIDFromDoc", func(t *testing.T) {
		connStore, err := New(&prov)
		require.NoError(t, err)

		err = connStore.SaveDIDFromDoc(mockdiddoc.GetMockDIDDoc())
		require.NoError(t, err)
	})

	t.Run("SaveDIDByResolving success", func(t *testing.T) {
		cs, err := New(&prov)
		require.NoError(t, err)

		err = cs.SaveDIDByResolving(mockdiddoc.GetMockDIDDoc().ID)
		require.NoError(t, err)
	})

	t.Run("SaveDIDByResolving error", func(t *testing.T) {
		prov := ctx{
			store: mockstorage.NewMockStoreProvider(),
			vdr:   &mockvdri.MockVDRIRegistry{ResolveErr: fmt.Errorf("resolve error")},
		}

		cs, err := New(&prov)
		require.NoError(t, err)

		err = cs.SaveDIDByResolving("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
	})
}
