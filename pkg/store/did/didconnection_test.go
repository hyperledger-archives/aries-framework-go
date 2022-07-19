/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

type ctx struct {
	store storage.Provider
	vdr   vdrapi.Registry
}

func (c *ctx) StorageProvider() storage.Provider {
	return c.store
}

func (c *ctx) VDRegistry() vdrapi.Registry {
	return c.vdr
}

func TestBaseConnectionStore(t *testing.T) {
	prov := ctx{
		store: mockstorage.NewMockStoreProvider(),
		vdr: &mockvdr.MockVDRegistry{
			CreateValue:  mockdiddoc.GetMockDIDDoc(t, false),
			ResolveValue: mockdiddoc.GetMockDIDDoc(t, false),
		},
	}

	t.Run("New", func(t *testing.T) {
		_, err := NewConnectionStore(&prov)
		require.NoError(t, err)

		_, err = NewConnectionStore(&ctx{
			store: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("store error"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
	})

	t.Run("SaveDID error", func(t *testing.T) {
		cs, err := NewConnectionStore(&ctx{
			store: &mockstorage.MockStoreProvider{
				Store: &mockstorage.MockStore{
					Store:  map[string]mockstorage.DBEntry{},
					ErrPut: fmt.Errorf("put error"),
				},
			},
			vdr: &mockvdr.MockVDRegistry{
				CreateValue:  mockdiddoc.GetMockDIDDoc(t, false),
				ResolveValue: mockdiddoc.GetMockDIDDoc(t, false),
			},
		})
		require.NoError(t, err)

		err = cs.SaveDID("did", "key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "put error")
	})

	t.Run("SaveDID + GetDID", func(t *testing.T) {
		connStore, err := NewConnectionStore(&prov)
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
		connStore, err := NewConnectionStore(&prov)
		require.NoError(t, err)

		err = connStore.SaveDIDFromDoc(mockdiddoc.GetMockDIDDocWithKeyAgreements(t))
		require.NoError(t, err)
	})

	t.Run("SaveDIDFromDoc with invalid DIDCommService type does not link keys to the DID", func(t *testing.T) {
		connStore, err := NewConnectionStore(&prov)
		require.NoError(t, err)

		mDIDDoc := mockdiddoc.GetMockDIDDocWithKeyAgreements(t)
		mDIDDoc.Service[0].Type = "invalid"

		err = connStore.SaveDIDFromDoc(mDIDDoc)
		require.NoError(t, err)

		_, err = connStore.GetDID(mDIDDoc.KeyAgreement[0].VerificationMethod.ID)
		require.EqualError(t, err, "did not found under given key")
	})

	t.Run("SaveDIDByResolving success", func(t *testing.T) {
		cs, err := NewConnectionStore(&prov)
		require.NoError(t, err)

		err = cs.SaveDIDByResolving(mockdiddoc.GetMockDIDDoc(t, false).ID)
		require.NoError(t, err)
	})

	t.Run("SaveDIDByResolving error", func(t *testing.T) {
		prov := ctx{
			store: mockstorage.NewMockStoreProvider(),
			vdr:   &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("resolve error")},
		}

		cs, err := NewConnectionStore(&prov)
		require.NoError(t, err)

		err = cs.SaveDIDByResolving("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve error")
	})
}
