/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"

	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
)

const (
	destinationURL  = "https://localhost:8090"
	successResponse = "success"
)

func TestGenerateInviteWithPublicDID(t *testing.T) {
	invite, err := GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})

	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		ID:    "12345678900987654321",
		Label: "Alice",
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithPublicDID(&Invitation{
		Label: "Alice",
		DID:   "did:example:ZadolSRQkehfo",
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestGenerateInviteWithKeyAndEndpoint(t *testing.T) {
	invite, err := GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		Label:           "Alice",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:            "12345678900987654321",
		Label:         "Alice",
		RecipientKeys: []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		RoutingKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)

	invite, err = GenerateInviteWithKeyAndEndpoint(&Invitation{
		ID:              "12345678900987654321",
		Label:           "Alice",
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.Error(t, err)
	require.Empty(t, invite)
}

func TestSendRequest(t *testing.T) {
	prov := New(nil, &mockProvider{})

	req := &Request{
		ID:    "5678876542345",
		Label: "Bob",
	}

	require.NoError(t, prov.SendExchangeRequest(req, destinationURL))
	require.Error(t, prov.SendExchangeRequest(nil, destinationURL))
}

func TestSendResponse(t *testing.T) {
	prov := New(nil, &mockProvider{})

	resp := &Response{
		ID: "12345678900987654321",
		ConnectionSignature: &ConnectionSignature{
			Type: "did:trustbloc:RQkehfoFssiwQRuihskwoPSR;spec/ed25519Sha512_single/1.0/ed25519Sha512_single",
		},
	}

	require.NoError(t, prov.SendExchangeResponse(resp, destinationURL))
	require.Error(t, prov.SendExchangeResponse(nil, destinationURL))
}

func TestCreateInvitation(t *testing.T) {
	prov := New(nil, &mockProvider{})
	inviteReq, err := prov.CreateInvitation()
	require.NoError(t, err)
	require.NotNil(t, inviteReq)
	require.Equal(t, inviteReq.Invitation.Type, connectionInvite)
	require.Equal(t, inviteReq.Invitation.Label, "agent")
	require.NotEmpty(t, inviteReq.Invitation.ID)
	require.Equal(t, inviteReq.Invitation.ServiceEndpoint, "endpoint")
}

type mockProvider struct {
}

func (p *mockProvider) OutboundTransport() transport.OutboundTransport {
	return mocktransport.NewOutboundTransport(successResponse)
}

func (p *mockProvider) ProtocolConfig() api.ProtocolConfig {
	return &mockProtocolConfig{}
}

type mockProtocolConfig struct {
}

func (m *mockProtocolConfig) AgentLabel() string {
	return "agent"
}

func (m *mockProtocolConfig) AgentServiceEndpoint() string {
	return "endpoint"
}
