/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/log"
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
	module := fmt.Sprintf("sample-module-caller-info-%d-%d", rand.Intn(1000), rand.Intn(1000)) //nolint:gosec

	require.True(t, IsCallerInfoEnabled(module, log.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, log.DEBUG))
	require.True(t, IsCallerInfoEnabled(module, log.INFO))
	require.True(t, IsCallerInfoEnabled(module, log.ERROR))
	require.True(t, IsCallerInfoEnabled(module, log.WARNING))

	ShowCallerInfo(module, log.CRITICAL)
	ShowCallerInfo(module, log.DEBUG)
	HideCallerInfo(module, log.INFO)
	HideCallerInfo(module, log.ERROR)
	HideCallerInfo(module, log.WARNING)

	require.True(t, IsCallerInfoEnabled(module, log.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, log.DEBUG))
	require.False(t, IsCallerInfoEnabled(module, log.INFO))
	require.False(t, IsCallerInfoEnabled(module, log.ERROR))
	require.False(t, IsCallerInfoEnabled(module, log.WARNING))

	require.True(t, IsCallerInfoEnabled(module, log.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, log.DEBUG))
	require.False(t, IsCallerInfoEnabled(module, log.INFO))
	require.False(t, IsCallerInfoEnabled(module, log.ERROR))
	require.False(t, IsCallerInfoEnabled(module, log.WARNING))
}

func verifyLevels(t *testing.T, module string, enabled, disabled []log.Level) {
	for _, level := range enabled {
		actual := IsEnabledFor(module, level)
		require.True(t, actual, "expected level [%s] to be enabled for module [%s]", ParseString(level), module)
	}

	for _, level := range disabled {
		actual := IsEnabledFor(module, level)
		require.False(t, actual, "expected level [%s] to be disabled for module [%s]", ParseString(level), module)
	}
}
