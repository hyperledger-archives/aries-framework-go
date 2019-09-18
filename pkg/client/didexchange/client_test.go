/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{})})
		require.NoError(t, err)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to DIDExchange Service failed")
	})
}

func TestClient_CreateInvitation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{}),
			WalletValue: &mockwallet.CloseableWallet{}, InboundEndpointValue: "endpoint"})
		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation()
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Invitation.Label)
		require.NotEmpty(t, inviteReq.Invitation.ID)
		require.Equal(t, "endpoint", inviteReq.Invitation.ServiceEndpoint)
	})

	t.Run("test error from createSigningKey", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{}),
			WalletValue: &mockwallet.CloseableWallet{CreateSigningKeyErr: fmt.Errorf("createSigningKeyErr")}})
		require.NoError(t, err)
		_, err = c.CreateInvitation()
		require.Error(t, err)
		require.Contains(t, err.Error(), "createSigningKeyErr")
	})

}

func TestClient_QueryConnectionByID(t *testing.T) {
	c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{})})
	require.NoError(t, err)

	result, err := c.QueryConnectionByID("sample-id")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ConnectionID)
}

func TestClient_RemoveConnection(t *testing.T) {
	c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{})})
	require.NoError(t, err)

	err = c.RemoveConnection("sample-id")
	require.NoError(t, err)
}

func TestClient_QueryConnectionsByParams(t *testing.T) {
	c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockProvider{})})
	require.NoError(t, err)

	results, err := c.QueryConnections(&QueryConnectionsParams{InvitationKey: "sample-inv-key"})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		require.NotNil(t, result)
		require.NotNil(t, result.ConnectionID)
	}
}

type mockProvider struct {
}

func (m *mockProvider) OutboundDispatcher() dispatcher.Outbound {
	return &mockdispatcher.MockOutbound{}
}

func (m *mockProvider) DIDWallet() wallet.DIDCreator {
	return &mockwallet.CloseableWallet{}
}
