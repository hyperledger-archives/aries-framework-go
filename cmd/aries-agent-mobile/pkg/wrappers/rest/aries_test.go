/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
)

func TestNewAries(t *testing.T) {
	t.Run("test it creates a rest agent instance with endpoints", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)
		require.NotNil(t, a.endpoints)
		require.GreaterOrEqual(t, len(a.endpoints), 1)
	})
}

func TestAries_GetIntroduceController(t *testing.T) {
	t.Run("test it creates an introduce controller instance", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetVerifiableController(t *testing.T) {
	t.Run("test it creates a verifiable controller instance", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetVerifiableController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetDIDExchangeController(t *testing.T) {
	t.Run("test it creates a did exchange controller instance", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		de, err := a.GetDIDExchangeController()
		require.NoError(t, err)
		require.NotNil(t, de)
	})
}
