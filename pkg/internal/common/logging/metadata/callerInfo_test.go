/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallerInfoSetting(t *testing.T) {
	ci := newCallerInfo()
	mod := "sample-module-name"

	// By default caller info should be enabled if not set
	require.True(t, ci.IsCallerInfoEnabled(mod, DEBUG), "Callerinfo supposed to be enabled for this level")
	require.True(t, ci.IsCallerInfoEnabled(mod, INFO), "Callerinfo supposed to be enabled for this level")
	require.True(t, ci.IsCallerInfoEnabled(mod, WARNING), "Callerinfo supposed to be enabled for this level")
	require.True(t, ci.IsCallerInfoEnabled(mod, ERROR), "Callerinfo supposed to be enabled for this level")
	require.True(t, ci.IsCallerInfoEnabled(mod, CRITICAL), "Callerinfo supposed to be enabled for this level")

	ci.HideCallerInfo(mod, DEBUG)
	require.False(t, ci.IsCallerInfoEnabled(mod, DEBUG), "Callerinfo supposed to be disabled for this level")

	ci.ShowCallerInfo(mod, DEBUG)
	require.True(t, ci.IsCallerInfoEnabled(mod, DEBUG), "Callerinfo supposed to be enabled for this level")

	ci.HideCallerInfo(mod, WARNING)
	require.False(t, ci.IsCallerInfoEnabled(mod, WARNING), "Callerinfo supposed to be disabled for this level")

	ci.ShowCallerInfo(mod, WARNING)
	require.True(t, ci.IsCallerInfoEnabled(mod, WARNING), "Callerinfo supposed to be enabled for this level")

	ci.HideCallerInfo(mod, DEBUG)
	require.False(t, ci.IsCallerInfoEnabled(mod, DEBUG), "Callerinfo supposed to be disabled for this level")

	ci.ShowCallerInfo(mod, DEBUG)
	require.True(t, ci.IsCallerInfoEnabled(mod, DEBUG), "Callerinfo supposed to be enabled for this level")

	// By default caller info should be enabled for any module name not set before
	moduleNames := []string{"sample-module-name-doesnt-exists", "", "@$#@$@"}
	for _, moduleName := range moduleNames {
		require.True(t, ci.IsCallerInfoEnabled(moduleName, INFO), "Callerinfo supposed to be enabled for this level")
		require.True(t, ci.IsCallerInfoEnabled(moduleName, WARNING), "Callerinfo supposed to be enabled for this level")
		require.True(t, ci.IsCallerInfoEnabled(moduleName, ERROR), "Callerinfo supposed to be enabled for this level")
		require.True(t, ci.IsCallerInfoEnabled(moduleName, CRITICAL), "Callerinfo supposed to be enabled for this level")
		require.True(t, ci.IsCallerInfoEnabled(moduleName, DEBUG), "Callerinfo supposed to be enabled for this level")
	}
}
