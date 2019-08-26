/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/support"

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
		mockSvcCreator := func(prv api.Provider) (api.ProtocolSvc, error) {
			return mockProtocolSvc{getAPIHandlersValue: []api.Handler{support.NewHTTPHandler("testPath", "", nil)}}, nil
		}
		prov, err := New(WithProtocolSvcCreator(mockSvcCreator))
		require.NoError(t, err)
		exist := false
		for _, v := range prov.apiHandlers {
			if v.Path() == "testPath" {
				exist = true
				break
			}
		}
		require.True(t, exist)
	})

	t.Run("test error from protocol service", func(t *testing.T) {
		newMockSvc := func(prv api.Provider) (api.ProtocolSvc, error) {
			return nil, errors.New("error creating the protocol")
		}
		_, err := New(WithProtocolSvcCreator(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the protocol")
	})
}

type mockProtocolSvc struct {
	getAPIHandlersValue []api.Handler
}

func (m mockProtocolSvc) GetAPIHandlers() []api.Handler {
	return m.getAPIHandlersValue
}
