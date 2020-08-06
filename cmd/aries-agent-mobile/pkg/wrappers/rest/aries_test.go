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
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetVerifiableController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetVerifiableController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetDIDExchangeController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		de, err := a.GetDIDExchangeController()
		require.NoError(t, err)
		require.NotNil(t, de)
	})
}

func TestAries_GetIssueCredentialController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		ic, err := a.GetIssueCredentialController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}

func TestAries_GetPresentProofController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetPresentProofController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetVDRIController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetVDRIController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetMediatorController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetMediatorController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetMessagingController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetMessagingController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}

func TestAries_GetOutOfBandController(t *testing.T) {
	t.Run("it creates a controller", func(t *testing.T) {
		a, err := NewAries(&config.Options{AgentURL: mockAgentURL})
		require.NoError(t, err)
		require.NotNil(t, a)

		controller, err := a.GetOutOfBandController()
		require.NoError(t, err)
		require.NotNil(t, controller)
	})
}
