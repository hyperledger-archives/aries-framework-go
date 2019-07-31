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

	sampleCallerInfoSetting := newCallerInfo()
	sampleModuleName := "sample-module-name"

	//By default caller info should be enabled if not set
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, DEBUG), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, INFO), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, WARNING), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, ERROR), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, CRITICAL), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, DEBUG), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, DEBUG), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, WARNING)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, WARNING), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, WARNING)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, WARNING), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, DEBUG), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, DEBUG), "Callerinfo supposed to be enabled for this level")

	//By default caller info should be enabled for any module name not set before
	moduleNames := []string{"sample-module-name-doesnt-exists", "", "@$#@$@"}
	for _, moduleName := range moduleNames {
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, INFO), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, WARNING), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, ERROR), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, CRITICAL), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, DEBUG), "Callerinfo supposed to be enabled for this level")
	}
}
