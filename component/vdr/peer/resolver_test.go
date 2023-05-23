/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
)

const peerDID = "did:peer:1234"

func TestPeerDIDResolver(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		context := []string{"https://w3id.org/did/v1"}
		// save did document
		vdr, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		err = vdr.storeDID(&did.Doc{Context: context, ID: peerDID}, nil)
		require.NoError(t, err)

		docResolution, err := vdr.Read(peerDID)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, peerDID, docResolution.DIDDocument.ID)
	})
	t.Run("test empty doc id", func(t *testing.T) {
		v, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		_, err = v.Read("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "ID is mandatory")
	})
}
