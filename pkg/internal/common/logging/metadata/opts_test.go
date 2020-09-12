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
)

func TestLevels(t *testing.T) {
	module := "sample-module-critical"
	SetLevel(module, CRITICAL)
	require.Equal(t, CRITICAL, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL}, []Level{ERROR, WARNING, INFO, DEBUG})

	module = "sample-module-error"
	SetLevel(module, ERROR)
	require.Equal(t, ERROR, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR}, []Level{WARNING, INFO, DEBUG})

	module = "sample-module-warning"
	SetLevel(module, WARNING)
	require.Equal(t, WARNING, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING}, []Level{INFO, DEBUG})

	module = "sample-module-info"
	SetLevel(module, INFO)
	require.Equal(t, INFO, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING, INFO}, []Level{DEBUG})

	module = "sample-module-debug"
	SetLevel(module, DEBUG)
	require.Equal(t, DEBUG, GetLevel(module))
	verifyLevels(t, module, []Level{CRITICAL, ERROR, WARNING, INFO, DEBUG}, []Level{})
}

func TestCallerInfos(t *testing.T) {
	module := fmt.Sprintf("sample-module-caller-info-%d-%d", rand.Intn(1000), rand.Intn(1000)) //nolint:gosec

	require.True(t, IsCallerInfoEnabled(module, CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, DEBUG))
	require.True(t, IsCallerInfoEnabled(module, INFO))
	require.True(t, IsCallerInfoEnabled(module, ERROR))
	require.True(t, IsCallerInfoEnabled(module, WARNING))

	ShowCallerInfo(module, CRITICAL)
	ShowCallerInfo(module, DEBUG)
	HideCallerInfo(module, INFO)
	HideCallerInfo(module, ERROR)
	HideCallerInfo(module, WARNING)

	require.True(t, IsCallerInfoEnabled(module, CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, DEBUG))
	require.False(t, IsCallerInfoEnabled(module, INFO))
	require.False(t, IsCallerInfoEnabled(module, ERROR))
	require.False(t, IsCallerInfoEnabled(module, WARNING))

	require.True(t, IsCallerInfoEnabled(module, CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, DEBUG))
	require.False(t, IsCallerInfoEnabled(module, INFO))
	require.False(t, IsCallerInfoEnabled(module, ERROR))
	require.False(t, IsCallerInfoEnabled(module, WARNING))
}

func verifyLevels(t *testing.T, module string, enabled, disabled []Level) {
	for _, level := range enabled {
		actual := IsEnabledFor(module, level)
		require.True(t, actual, "expected level [%s] to be enabled for module [%s]", ParseString(level), module)
	}

	for _, level := range disabled {
		actual := IsEnabledFor(module, level)
		require.False(t, actual, "expected level [%s] to be disabled for module [%s]", ParseString(level), module)
	}
}
