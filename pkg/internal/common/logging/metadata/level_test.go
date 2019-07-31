/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogLevels(t *testing.T) {

	mlevel := newModuledLevels()

	mlevel.SetLevel("module-xyz-info", INFO)
	mlevel.SetLevel("module-xyz-debug", DEBUG)
	mlevel.SetLevel("module-xyz-error", ERROR)
	mlevel.SetLevel("module-xyz-warning", WARNING)
	mlevel.SetLevel("module-xyz-critical", CRITICAL)

	//Run info level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-info", DEBUG))

	//Run debug level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", INFO))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", DEBUG))

	//Run warning level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", DEBUG))

	//Run error level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", DEBUG))

	//Run error critical checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-critical", CRITICAL))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", DEBUG))

	//Run default log level check --> which is info level
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-random-module", DEBUG))

}
