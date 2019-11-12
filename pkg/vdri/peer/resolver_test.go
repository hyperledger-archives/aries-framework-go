/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

const peerDID = "did:peer:1234"

func TestPeerDIDResolver(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		context := []string{"https://w3id.org/did/v1"}
		// save did document
		vdri, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		err = vdri.Store(&did.Doc{Context: context, ID: peerDID}, nil)
		require.NoError(t, err)

		doc, err := vdri.Read(peerDID)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, peerDID, doc.ID)
	})
	t.Run("test empty doc id", func(t *testing.T) {
		vdri, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		_, err = vdri.Read("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "ID is mandatory")
	})
}
