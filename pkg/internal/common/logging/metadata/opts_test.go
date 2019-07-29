/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/stretchr/testify/require"
)

func TestLevels(t *testing.T) {

	module := "sample-module-critical"
	SetLevel(module, log.CRITICAL)
	require.Equal(t, log.CRITICAL, GetLevel(module))
	verifyLevels(t, module, []log.Level{log.CRITICAL}, []log.Level{log.ERROR, log.WARNING, log.INFO, log.DEBUG})

	module = "sample-module-error"
	SetLevel(module, log.ERROR)
	require.Equal(t, log.ERROR, GetLevel(module))
	verifyLevels(t, module, []log.Level{log.CRITICAL, log.ERROR}, []log.Level{log.WARNING, log.INFO, log.DEBUG})

	module = "sample-module-warning"
	SetLevel(module, log.WARNING)
	require.Equal(t, log.WARNING, GetLevel(module))
	verifyLevels(t, module, []log.Level{log.CRITICAL, log.ERROR, log.WARNING}, []log.Level{log.INFO, log.DEBUG})

	module = "sample-module-info"
	SetLevel(module, log.INFO)
	require.Equal(t, log.INFO, GetLevel(module))
	verifyLevels(t, module, []log.Level{log.CRITICAL, log.ERROR, log.WARNING, log.INFO}, []log.Level{log.DEBUG})

	module = "sample-module-debug"
	SetLevel(module, log.DEBUG)
	require.Equal(t, log.DEBUG, GetLevel(module))
	verifyLevels(t, module, []log.Level{log.CRITICAL, log.ERROR, log.WARNING, log.INFO, log.DEBUG}, []log.Level{})

}

func TestCallerInfos(t *testing.T) {
	module := "sample-module-caller-info"

	require.True(t, GetLoggerOpts(module, log.CRITICAL).CallerInfoEnabled)
	require.True(t, GetLoggerOpts(module, log.DEBUG).CallerInfoEnabled)
	require.True(t, GetLoggerOpts(module, log.INFO).CallerInfoEnabled)
	require.True(t, GetLoggerOpts(module, log.ERROR).CallerInfoEnabled)
	require.True(t, GetLoggerOpts(module, log.WARNING).CallerInfoEnabled)

	ShowCallerInfo(module, log.CRITICAL)
	ShowCallerInfo(module, log.DEBUG)
	HideCallerInfo(module, log.INFO)
	HideCallerInfo(module, log.ERROR)
	HideCallerInfo(module, log.WARNING)

	require.True(t, GetLoggerOpts(module, log.CRITICAL).CallerInfoEnabled)
	require.True(t, GetLoggerOpts(module, log.DEBUG).CallerInfoEnabled)
	require.False(t, GetLoggerOpts(module, log.INFO).CallerInfoEnabled)
	require.False(t, GetLoggerOpts(module, log.ERROR).CallerInfoEnabled)
	require.False(t, GetLoggerOpts(module, log.WARNING).CallerInfoEnabled)

	require.True(t, IsCallerInfoEnabled(module, log.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, log.DEBUG))
	require.False(t, IsCallerInfoEnabled(module, log.INFO))
	require.False(t, IsCallerInfoEnabled(module, log.ERROR))
	require.False(t, IsCallerInfoEnabled(module, log.WARNING))
}

func verifyLevels(t *testing.T, module string, enabled []log.Level, disabled []log.Level) {
	for _, level := range enabled {
		require.True(t, IsEnabledFor(module, level), "expected level [%s] to be enabled for module [%s]", ParseString(level), module)
		require.True(t, GetLoggerOpts(module, level).LevelEnabled, "expected level [%s] to be enabled for module [%s] in logger opts", ParseString(level), module)
	}
	for _, level := range disabled {
		require.False(t, IsEnabledFor(module, level), "expected level [%s] to be disabled for module [%s]", ParseString(level), module)
		require.False(t, GetLoggerOpts(module, level).LevelEnabled, "expected level [%s] to be disabled for module [%s] in logger opts", ParseString(level), module)
	}
}
