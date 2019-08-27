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
	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
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
	res, err := c.CreateInvitation()
	require.NoError(t, err)
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.NotEmpty(t, res.Invitation)
	require.NotEmpty(t, res.Invitation.ID)
	require.NotEmpty(t, res.Invitation.URL)

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
