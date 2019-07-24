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

func TestLogLevels(t *testing.T) {

	mlevel := ModuleLevels{}

	mlevel.SetLevel("module-xyz-info", api.INFO)
	mlevel.SetLevel("module-xyz-debug", api.DEBUG)
	mlevel.SetLevel("module-xyz-error", api.ERROR)
	mlevel.SetLevel("module-xyz-warning", api.WARNING)
	mlevel.SetLevel("module-xyz-critical", api.CRITICAL)

	//Run info level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", api.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", api.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", api.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-info", api.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-info", api.DEBUG))

	//Run debug level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", api.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", api.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", api.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", api.INFO))
	require.True(t, mlevel.IsEnabledFor("module-xyz-debug", api.DEBUG))

	//Run warning level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", api.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", api.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-warning", api.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", api.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-warning", api.DEBUG))

	//Run error level checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", api.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-error", api.ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", api.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", api.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-error", api.DEBUG))

	//Run error critical checks
	require.True(t, mlevel.IsEnabledFor("module-xyz-critical", api.CRITICAL))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", api.ERROR))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", api.WARNING))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", api.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-critical", api.DEBUG))

	//Run default log level check --> which is info level
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", api.CRITICAL))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", api.ERROR))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", api.WARNING))
	require.True(t, mlevel.IsEnabledFor("module-xyz-random-module", api.INFO))
	require.False(t, mlevel.IsEnabledFor("module-xyz-random-module", api.DEBUG))

}
