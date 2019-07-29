/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

func TestCallerInfoSetting(t *testing.T) {

	sampleCallerInfoSetting := newCallerInfo()
	sampleModuleName := "sample-module-name"

	//By default caller info should be enabled if not set
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.DEBUG), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.INFO), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.WARNING), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.ERROR), "Callerinfo supposed to be enabled for this level")
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.CRITICAL), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, log.DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.DEBUG), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, log.DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.DEBUG), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, log.WARNING)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.WARNING), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, log.WARNING)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.WARNING), "Callerinfo supposed to be enabled for this level")

	sampleCallerInfoSetting.HideCallerInfo(sampleModuleName, log.DEBUG)
	require.False(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.DEBUG), "Callerinfo supposed to be disabled for this level")

	sampleCallerInfoSetting.ShowCallerInfo(sampleModuleName, log.DEBUG)
	require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(sampleModuleName, log.DEBUG), "Callerinfo supposed to be enabled for this level")

	//By default caller info should be enabled for any module name not set before
	moduleNames := []string{"sample-module-name-doesnt-exists", "", "@$#@$@"}
	for _, moduleName := range moduleNames {
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, log.INFO), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, log.WARNING), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, log.ERROR), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, log.CRITICAL), "Callerinfo supposed to be enabled for this level")
		require.True(t, sampleCallerInfoSetting.IsCallerInfoEnabled(moduleName, log.DEBUG), "Callerinfo supposed to be enabled for this level")
	}
}
