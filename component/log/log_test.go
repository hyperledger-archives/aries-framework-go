/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/log/internal/metadata"
	"github.com/hyperledger/aries-framework-go/component/log/internal/modlog"

	"github.com/hyperledger/aries-framework-go/spi/log"
)

// TestDefaultLogger tests default logging feature when no custom logging provider is supplied via 'Initialize()' call.
func TestDefaultLogger(t *testing.T) {
	defer func() { loggerProviderOnce = sync.Once{} }()

	const module = "sample-module"

	// get new logger since Initialize is not called, default logger implementation will be used
	logger := New(module)

	// force logger instance loading to switch output of logger to buffer for testing
	logger.Infof("sample output")
	modlog.SwitchLogOutputToBuffer(logger.instance)

	// verify default logger
	modlog.VerifyDefaultLogging(t, logger, module, metadata.SetLevel)
}

// TestAllLevels tests logging level behaviour
// logging levels can be set per modules, if not set then it will default to 'INFO'.
func TestAllLevels(t *testing.T) {
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

// TestCallerInfos callerinfo behavior which displays caller function details in log lines
// CallerInfo is available in default logger.
// Based on implementation it may not be available for custom logger.
func TestCallerInfos(t *testing.T) {
	module := "sample-module-caller-info"

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
}

// TestLogLevel testing 'LogLevel()' used for parsing log levels from strings.
func TestLogLevel(t *testing.T) {
	verifyLevelsNoError := func(expected log.Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(log.CRITICAL, "critical", "CRITICAL", "CriticAL")
	verifyLevelsNoError(log.ERROR, "error", "ERROR", "ErroR")
	verifyLevelsNoError(log.WARNING, "warning", "WARNING", "WarninG")
	verifyLevelsNoError(log.DEBUG, "debug", "DEBUG", "DebUg")
	verifyLevelsNoError(log.INFO, "info", "INFO", "iNFo")
}

// TestParseLevelError testing 'LogLevel()' used for parsing log levels from strings.
func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func verifyLevels(t *testing.T, module string, enabled, disabled []log.Level) {
	t.Helper()

	for _, level := range enabled {
		levelStr := metadata.ParseString(level)
		require.True(t, IsEnabledFor(module, level),
			"expected level [%s] to be enabled for module [%s]", levelStr, module)
	}

	for _, level := range disabled {
		levelStr := metadata.ParseString(level)
		require.False(t, IsEnabledFor(module, level),
			"expected level [%s] to be disabled for module [%s]", levelStr, module)
	}
}
