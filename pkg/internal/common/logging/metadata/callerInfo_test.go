/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
)

func TestCallerInfoSetting(t *testing.T) {

	sampleCallerInfoSetting := CallerInfo{}
	sampleModuleName := "sample-module-name"

	//By default caller info should be enabled if not set
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.DEBUG), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.INFO), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.WARNING), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.ERROR), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.CRITICAL), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, api.DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.DEBUG), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, api.DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.DEBUG), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, api.WARNING)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.WARNING), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, api.WARNING)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.WARNING), "Callerinfo supposed to be disabled for this level")

	//Reset existing caller info setting
	sampleCallerInfoSetting.showcaller = nil

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, api.DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.DEBUG), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, api.DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.DEBUG), "Callerinfo supposed to be disabled for this level")

	//Reset existing caller info setting
	sampleCallerInfoSetting.showcaller = nil

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, api.WARNING)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.WARNING), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, api.WARNING)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, api.WARNING), "Callerinfo supposed to be enabled for this level")

	//By default caller info should be enabled for any module name not set before
	moduleNames := []string{"sample-module-name-doesnt-exists", "", "@$#@$@"}
	for _, moduleName := range moduleNames {
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, api.INFO), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, api.WARNING), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, api.ERROR), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, api.CRITICAL), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, api.DEBUG), "Callerinfo supposed to be enabled for this level")
	}
}
