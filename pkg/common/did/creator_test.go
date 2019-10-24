/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	d "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
)

func getMockDID() *d.Doc {
	return &d.Doc{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      "did:example:123456789abcdefghi#inbox",
		Service: []d.Service{{
			ServiceEndpoint: "https://localhost:8090",
		}},
	}
}

func TestPeerDIDCreator(t *testing.T) {
	t.Run("create new local DID ", func(t *testing.T) {
		creator := NewPeerDIDCreator(&mockProvider{})
		require.NotNil(t, creator)

		did, err := creator.CreateDID()
		require.NotNil(t, did)
		require.NoError(t, err)

		require.Equal(t, did, getMockDID())
	})

	t.Run("get DID ", func(t *testing.T) {
		creator := NewPeerDIDCreator(&mockProvider{})
		require.NotNil(t, creator)

		did, err := creator.GetDID(getMockDID().ID)
		require.NotNil(t, did)
		require.NoError(t, err)

		require.Equal(t, did, getMockDID())
	})
}

// mockProvider is mock provider for DID creator
type mockProvider struct {
}

func (m *mockProvider) DIDWallet() didcreator.DIDCreator {
	return &mockwallet.CloseableWallet{MockDID: getMockDID()}
}
