/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
)

func TestNewAries(t *testing.T) {
	t.Run("test it creates a rest client instance with endpoints", func(t *testing.T) {
		a := NewAries(&api.Options{})
		require.NotNil(t, a)
		require.NotNil(t, a.endpoints)
		require.GreaterOrEqual(t, len(a.endpoints), 1)
	})
}

func TestAriesREST_GetIntroduceController(t *testing.T) {
	t.Run("test it creates an introduce controller instance", func(t *testing.T) {
		a := NewAries(&api.Options{})

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}
