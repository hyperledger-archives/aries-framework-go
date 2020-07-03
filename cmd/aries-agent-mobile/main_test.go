/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesagent

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/command"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/rest"
)

func TestNewAriesAgent(t *testing.T) {
	t.Run("test it creates a local agent", func(t *testing.T) {
		isLocal := true
		localAries, err := NewAriesAgent(isLocal)
		require.NoError(t, err)
		require.NotNil(t, localAries)

		var a *command.Aries
		require.IsType(t, a, localAries)
	})

	t.Run("test it creates a remote agent", func(t *testing.T) {
		isLocal := false
		remoteAries, err := NewAriesAgent(isLocal)
		require.NoError(t, err)
		require.NotNil(t, remoteAries)

		var a *rest.AriesREST
		require.IsType(t, a, remoteAries)
	})
}
