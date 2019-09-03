/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		_, err := New(&mockProvider{serviceValue: didexchange.New(nil, &mockOutboundTransport{})})
		require.NoError(t, err)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockProvider{serviceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockProvider{serviceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to didexchange.Service failed")
	})
}

func TestCreateInvitation(t *testing.T) {
	c, err := New(&mockProvider{serviceValue: didexchange.New(nil, &mockOutboundTransport{})})
	require.NoError(t, err)
	inviteReq, err := c.CreateInvitation()
	require.NoError(t, err)
	require.NotNil(t, inviteReq)
	require.NotEmpty(t, inviteReq.Invitation.Label)
	require.NotEmpty(t, inviteReq.Invitation.ID)
	require.NotEmpty(t, inviteReq.Invitation.ServiceEndpoint)

}

//mockProvider mocks provider needed for did exchange service initialization
type mockProvider struct {
	serviceValue interface{}
	serviceErr   error
}

func (p *mockProvider) Service(id string) (interface{}, error) {
	return p.serviceValue, p.serviceErr
}

type mockOutboundTransport struct {
}

func (p *mockOutboundTransport) OutboundTransport() transport.OutboundTransport {
	return mocktransport.NewOutboundTransport("success")
}

func (p *mockOutboundTransport) ProtocolConfig() api.ProtocolConfig {
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
