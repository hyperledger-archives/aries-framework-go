/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logging

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/internal/common/logging/modlog"
)

//TestDefaultLogger tests default logging feature when no custom logging provider is supplied through 'Initialize()' call
func TestDefaultLogger(t *testing.T) {

	defer func() { loggerProviderOnce = sync.Once{} }()

	const module = "sample-module"
	logger := NewLogger(module)

	//force logger instance loading
	logger.Infof("sample output")

	modlog.SwitchLogOutputToBuffer(logger.instance)
	modlog.VerifyDefaultLogging(t, logger, module, SetLevel)

}

//TestDefaultLogger tests custom logging feature when custom logging provider is supplied through 'Initialize()' call
func TestCustomLogger(t *testing.T) {

	defer func() { loggerProviderOnce = sync.Once{} }()

	const module = "sample-module"

	Initialize(modlog.NewCustomLoggingProvider())

	logger := NewLogger(module)

	modlog.VerifyCustomLogger(t, logger, module)
}

//TestAllLevels tests logging level behaviour
//logging levels can be set per modules, if not set then it will default to 'INFO'
func TestAllLevels(t *testing.T) {

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

//TestCallerInfos callerinfo behavior which displays caller function details in log lines
//CallerInfo is available in default logger.
//Based on implementation it may not be available for custom logger
func TestCallerInfos(t *testing.T) {
	module := "sample-module-caller-info"

	ShowCallerInfo(module, api.CRITICAL)
	ShowCallerInfo(module, api.DEBUG)
	HideCallerInfo(module, api.INFO)
	HideCallerInfo(module, api.ERROR)
	HideCallerInfo(module, api.WARNING)

	require.True(t, IsCallerInfoEnabled(module, api.CRITICAL))
	require.True(t, IsCallerInfoEnabled(module, api.DEBUG))
	require.False(t, IsCallerInfoEnabled(module, api.INFO))
	require.False(t, IsCallerInfoEnabled(module, api.ERROR))
	require.False(t, IsCallerInfoEnabled(module, api.WARNING))

}

//TestLogLevel testing 'LogLevel()' used for parsing log levels from strings
func TestLogLevel(t *testing.T) {

	verifyLevelsNoError := func(expected api.Level, levels ...string) {
		for _, level := range levels {
			actual, err := LogLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(api.CRITICAL, "critical", "CRITICAL", "CriticAL")
	verifyLevelsNoError(api.ERROR, "error", "ERROR", "ErroR")
	verifyLevelsNoError(api.WARNING, "warning", "WARNING", "WarninG")
	verifyLevelsNoError(api.DEBUG, "debug", "DEBUG", "DebUg")
	verifyLevelsNoError(api.INFO, "info", "INFO", "iNFo")
}

//TestParseLevelError testing 'LogLevel()' used for parsing log levels from strings
func TestParseLevelError(t *testing.T) {

	verifyLevelError := func(expected api.Level, levels ...string) {
		for _, level := range levels {
			_, err := LogLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError(api.DEBUG, "", "D", "DE BUG", ".")

}

func verifyLevels(t *testing.T, module string, enabled []api.Level, disabled []api.Level) {
	for _, level := range enabled {
		require.True(t, IsEnabledFor(module, level), "expected level [%s] to be enabled for module [%s]", metadata.ParseString(level), module)
	}
	for _, level := range disabled {
		require.False(t, IsEnabledFor(module, level), "expected level [%s] to be disabled for module [%s]", metadata.ParseString(level), module)
	}
}
