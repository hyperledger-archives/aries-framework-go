/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"testing"

	"github.com/stretchr/testify/require"

	d "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
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

func TestLocalDIDCreator_CreateDID(t *testing.T) {
	creator := NewLocalDIDCreator(&mockProvider{})
	require.NotNil(t, creator)

	did, err := creator.CreateDID()
	require.NotNil(t, did)
	require.NoError(t, err)

	require.Equal(t, did, getMockDID())
}

// mockProvider is mock provider for DID creator
type mockProvider struct {
}

func (m *mockProvider) DIDWallet() wallet.DIDCreator {
	return &mockwallet.CloseableWallet{MockDID: getMockDID()}
}
