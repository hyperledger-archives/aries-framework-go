/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"

	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
	errors "golang.org/x/xerrors"
)

func TestNewProvider(t *testing.T) {
	t.Run("test new with default", func(t *testing.T) {
		prov, err := New()
		require.NoError(t, err)
		require.Empty(t, prov.OutboundTransport())
	})
	t.Run("test new with outbound transport", func(t *testing.T) {
		prov, err := New(WithOutboundTransport(mocktransport.NewOutboundTransport("success")))
		require.NoError(t, err)
		require.NotEmpty(t, prov.OutboundTransport())
	})
	t.Run("test error return from options", func(t *testing.T) {
		_, err := New(func(opts *Provider) error {
			return errors.New("error creating the framework option")
		})
		require.Error(t, err)
	})

	t.Run("test new with protocol service", func(t *testing.T) {
		mockSvcCreator := func(prv api.Provider) (dispatcher.Service, error) {
			return mockProtocolSvc{}, nil
		}
		prov, err := New(WithProtocols(mockSvcCreator))
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)

	})

	t.Run("test error from protocol service", func(t *testing.T) {
		newMockSvc := func(prv api.Provider) (dispatcher.Service, error) {
			return nil, errors.New("error creating the protocol")
		}
		_, err := New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the protocol")
	})
}

type mockProtocolSvc struct {
}

func (m mockProtocolSvc) Handle(msg dispatcher.DIDCommMsg) {

}

func (m mockProtocolSvc) Accept(msgType string) bool {
	return true
}

func (m mockProtocolSvc) Name() string {
	return "mockProtocolSvc"
}
