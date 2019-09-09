/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockOutboundTransport{})})
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
		c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockOutboundTransport{}),
			WalletValue: &wallet.CloseableWallet{CreateSigningKeyValue: &wallet.KeyInfo{}}})
		require.NoError(t, err)
		inviteReq, err := c.CreateInvitation()
		require.NoError(t, err)
		require.NotNil(t, inviteReq)
		require.NotEmpty(t, inviteReq.Invitation.Label)
		require.NotEmpty(t, inviteReq.Invitation.ID)
		require.NotEmpty(t, inviteReq.Invitation.ServiceEndpoint)
	})

	t.Run("test error from createSigningKey", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{ServiceValue: didexchange.New(nil, &mockOutboundTransport{}),
			WalletValue: &wallet.CloseableWallet{CreateSigningKeyErr: fmt.Errorf("createSigningKeyErr")}})
		require.NoError(t, err)
		_, err = c.CreateInvitation()
		require.Error(t, err)
		require.Contains(t, err.Error(), "createSigningKeyErr")
	})
}

type mockOutboundTransport struct {
}

func (p *mockOutboundTransport) OutboundTransport() transport.OutboundTransport {
	return didcomm.NewMockOutboundTransport("success")
}
