/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	mockSignatureValue = "mock-did-rotation-signature"
	myDID              = "did:peer:123456789abcdefghi"
	theirDID           = "did:test:theirDID"
	connectionID       = "test-connection-id"
)

func mockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	storeProv := mockstore.NewMockStoreProvider()

	prov := &mockprovider.Provider{
		StorageProviderValue:              storeProv,
		ProtocolStateStorageProviderValue: storeProv,
	}

	prov.VDRegistryValue = &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			switch didID {
			default:
				fallthrough
			case myDID:
				return &did.DocResolution{
					DIDDocument: mockdiddoc.GetMockDIDDocWithKeyAgreements(t),
				}, nil
			case theirDID:
				return &did.DocResolution{
					DIDDocument: mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, theirDID),
				}, nil
			}
		},
	}

	didStore, err := didstore.NewConnectionStore(prov)
	require.NoError(t, err)

	prov.DIDConnectionStoreValue = didStore

	prov.CryptoValue = &mockcrypto.Crypto{
		SignValue: []byte(mockSignatureValue),
	}

	prov.KMSValue = &mockkms.KeyManager{}

	didRotator, err := didrotate.New(prov)
	require.NoError(t, err)

	prov.DIDRotatorValue = *didRotator

	return prov
}

func TestNew(t *testing.T) {
	prov := mockProvider(t)

	_, err := New(prov)
	require.NoError(t, err)

	expectErr := fmt.Errorf("expected error")

	prov.StorageProviderValue = &mockstore.MockStoreProvider{ErrOpenStoreHandle: expectErr}

	_, err = New(prov)
	require.ErrorIs(t, err, expectErr)
}

func TestClient_RotateDID(t *testing.T) {
	c, err := New(mockProvider(t))
	require.NoError(t, err)

	err = c.RotateDID("a", "b", "c")
	require.Error(t, err)
}

func TestClient_CreateConnectionV2(t *testing.T) {
	expectErr := fmt.Errorf("expected error")

	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID, WithTheirLabel("their label"))
		require.NoError(t, err)
		require.NotEqual(t, "", connID)
	})

	t.Run("fail to resolve their did", func(t *testing.T) {
		prov := mockProvider(t)

		prov.VDRegistryValue = &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				switch didID {
				default:
					fallthrough
				case myDID:
					return &did.DocResolution{
						DIDDocument: mockdiddoc.GetMockDIDDocWithKeyAgreements(t),
					}, nil
				case theirDID:
					return nil, expectErr
				}
			},
		}

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "resolving their DID")
		require.Equal(t, "", connID)
	})

	t.Run("fail to save their did to did store", func(t *testing.T) {
		prov := mockProvider(t)

		prov.StorageProviderValue = mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			ErrPut: expectErr,
		})

		didStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)

		prov.DIDConnectionStoreValue = didStore

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to save theirDID")
		require.Equal(t, "", connID)
	})

	t.Run("fail to resolve my did when saving to did store", func(t *testing.T) {
		prov := mockProvider(t)

		prov.VDRegistryValue = &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				switch didID {
				default:
					fallthrough
				case myDID:
					return nil, expectErr
				case theirDID:
					return &did.DocResolution{
						DIDDocument: mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, theirDID),
					}, nil
				}
			},
		}

		didStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)

		prov.DIDConnectionStoreValue = didStore

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Contains(t, err.Error(), "failed to save myDID")
		require.Equal(t, "", connID)
	})

	t.Run("fail to resolve my did when saving to did store", func(t *testing.T) {
		prov := mockProvider(t)

		prov.VDRegistryValue = &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				switch didID {
				default:
					fallthrough
				case myDID:
					return &did.DocResolution{
						DIDDocument: mockdiddoc.GetMockDIDDocWithKeyAgreements(t),
					}, nil
				case theirDID:
					return &did.DocResolution{
						DIDDocument: &did.Doc{
							ID: theirDID,
						},
					}, nil
				}
			},
		}

		didStore, err := didstore.NewConnectionStore(prov)
		require.NoError(t, err)

		prov.DIDConnectionStoreValue = didStore

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create destination")
		require.Equal(t, "", connID)
	})

	t.Run("fail to save to connection store", func(t *testing.T) {
		prov := mockProvider(t)

		prov.ProtocolStateStorageProviderValue = mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			ErrPut: expectErr,
		})

		c, err := New(prov)
		require.NoError(t, err)

		connID, err := c.CreateConnectionV2(myDID, theirDID)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Equal(t, "", connID)
	})
}

func TestClient_SetConnectionToDIDCommV2(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		prov := mockProvider(t)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connectionID,
			State:        connection.StateNameCompleted,
		}))

		c, err := New(prov)
		require.NoError(t, err)

		err = c.SetConnectionToDIDCommV2(connectionID)
		require.NoError(t, err)
	})

	t.Run("fail: connection ID not found", func(t *testing.T) {
		prov := mockProvider(t)

		c, err := New(prov)
		require.NoError(t, err)

		err = c.SetConnectionToDIDCommV2(connectionID)
		require.Error(t, err)
		require.ErrorIs(t, err, storage.ErrDataNotFound)
	})

	t.Run("fail: saving updated connection", func(t *testing.T) {
		prov := mockProvider(t)

		store := mockstore.MockStore{Store: map[string]mockstore.DBEntry{}}

		prov.StorageProviderValue = mockstore.NewCustomMockStoreProvider(&store)

		connStore, err := connection.NewRecorder(prov)
		require.NoError(t, err)

		require.NoError(t, connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: connectionID,
			State:        connection.StateNameCompleted,
		}))

		expectErr := fmt.Errorf("expected error")

		store.ErrPut = expectErr

		c, err := New(prov)
		require.NoError(t, err)

		err = c.SetConnectionToDIDCommV2(connectionID)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
	})
}
