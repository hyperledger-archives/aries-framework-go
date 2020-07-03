/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAries(t *testing.T) {
	t.Run("test it creates an instance with a framework and handlers", func(t *testing.T) {
		a, err := NewAries()
		require.NoError(t, err)
		require.NotNil(t, a)
		require.NotNil(t, a.framework)
		require.NotNil(t, a.handlers)
	})
}

func TestAries_GetIntroduceController(t *testing.T) {
	t.Run("test it creates an introduce controller instance", func(t *testing.T) {
		a, err := NewAries()
		require.NoError(t, err)

		ic, err := a.GetIntroduceController()
		require.NoError(t, err)
		require.NotNil(t, ic)
	})
}
