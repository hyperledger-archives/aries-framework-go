/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/log"
)

func TestLogLevels(t *testing.T) {
	mlevel := newModuledLevels()

	mlevel.SetLevel("module-xyz-info", log.INFO)
	mlevel.SetLevel("module-xyz-debug", log.DEBUG)
	mlevel.SetLevel("module-xyz-error", log.ERROR)
	mlevel.SetLevel("module-xyz-warning", log.WARNING)
	mlevel.SetLevel("module-xyz-critical", log.CRITICAL)

	// Run info level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", log.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", log.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", log.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", log.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-info", log.DEBUG))

	// Run debug level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", log.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", log.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", log.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", log.INFO))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", log.DEBUG))

	// Run warning level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", log.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", log.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", log.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", log.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", log.DEBUG))

	// Run error level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", log.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", log.ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", log.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", log.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", log.DEBUG))

	// Run error critical checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-critical", log.CRITICAL))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", log.ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", log.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", log.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", log.DEBUG))

	// Run default log level check --> which is info level
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", log.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", log.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", log.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", log.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-random-module", log.DEBUG))
}
