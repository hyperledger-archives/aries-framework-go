/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package modlog

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
	"github.com/stretchr/testify/require"
)

func TestLevels(t *testing.T) {

	module := "sample-module-critical"
	SetLevel(module, api.CRITICAL)
	require.Equal(t, api.CRITICAL, GetLevel(module))
	verifyLevels(t, module, []api.Level{api.CRITICAL}, []api.Level{api.ERROR, api.WARNING, api.INFO, api.DEBUG})

	module = "sample-module-error"
	SetLevel(module, api.ERROR)
	require.Equal(t, api.ERROR, GetLevel(module))
	verifyLevels(t, module, []api.Level{api.CRITICAL, api.ERROR}, []api.Level{api.WARNING, api.INFO, api.DEBUG})

	module = "sample-module-warning"
	SetLevel(module, api.WARNING)
	require.Equal(t, api.WARNING, GetLevel(module))
	verifyLevels(t, module, []api.Level{api.CRITICAL, api.ERROR, api.WARNING}, []api.Level{api.INFO, api.DEBUG})

	module = "sample-module-info"
	SetLevel(module, api.INFO)
	require.Equal(t, api.INFO, GetLevel(module))
	verifyLevels(t, module, []api.Level{api.CRITICAL, api.ERROR, api.WARNING, api.INFO}, []api.Level{api.DEBUG})

	module = "sample-module-debug"
	SetLevel(module, api.DEBUG)
	require.Equal(t, api.DEBUG, GetLevel(module))
	verifyLevels(t, module, []api.Level{api.CRITICAL, api.ERROR, api.WARNING, api.INFO, api.DEBUG}, []api.Level{})

}

func TestCallerInfos(t *testing.T) {
	module := "sample-module-caller-info"

	require.True(t, getLoggerOpts(module, api.CRITICAL).callerInfoEnabled)
	require.True(t, getLoggerOpts(module, api.DEBUG).callerInfoEnabled)
	require.True(t, getLoggerOpts(module, api.INFO).callerInfoEnabled)
	require.True(t, getLoggerOpts(module, api.ERROR).callerInfoEnabled)
	require.True(t, getLoggerOpts(module, api.WARNING).callerInfoEnabled)

	ShowCallerInfo(module, api.CRITICAL)
	ShowCallerInfo(module, api.DEBUG)
	HideCallerInfo(module, api.INFO)
	HideCallerInfo(module, api.ERROR)
	HideCallerInfo(module, api.WARNING)

	require.True(t, getLoggerOpts(module, api.CRITICAL).callerInfoEnabled)
	require.True(t, getLoggerOpts(module, api.DEBUG).callerInfoEnabled)
	require.False(t, getLoggerOpts(module, api.INFO).callerInfoEnabled)
	require.False(t, getLoggerOpts(module, api.ERROR).callerInfoEnabled)
	require.False(t, getLoggerOpts(module, api.WARNING).callerInfoEnabled)

	require.True(t, IsCallerInfoEnabled(module, api.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, api.DEBUG))
	require.False(t, IsCallerInfoEnabled(module, api.INFO))
	require.False(t, IsCallerInfoEnabled(module, api.ERROR))
	require.False(t, IsCallerInfoEnabled(module, api.WARNING))
}

func verifyLevels(t *testing.T, module string, enabled []api.Level, disabled []api.Level) {
	for _, level := range enabled {
		require.True(t, IsEnabledFor(module, level), "expected level [%s] to be enabled for module [%s]", metadata.ParseString(level), module)
		require.True(t, getLoggerOpts(module, level).levelEnabled, "expected level [%s] to be enabled for module [%s] in logger opts", metadata.ParseString(level), module)
	}
	for _, level := range disabled {
		require.False(t, IsEnabledFor(module, level), "expected level [%s] to be disabled for module [%s]", metadata.ParseString(level), module)
		require.False(t, getLoggerOpts(module, level).levelEnabled, "expected level [%s] to be disabled for module [%s] in logger opts", metadata.ParseString(level), module)
	}
}
