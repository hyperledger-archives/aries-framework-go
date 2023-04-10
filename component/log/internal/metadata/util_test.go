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

func TestParseLevel(t *testing.T) {
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

func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func TestParseString(t *testing.T) {
	require.Equal(t, "CRITICAL", ParseString(log.CRITICAL))
	require.Equal(t, "ERROR", ParseString(log.ERROR))
	require.Equal(t, "WARNING", ParseString(log.WARNING))
	require.Equal(t, "DEBUG", ParseString(log.DEBUG))
	require.Equal(t, "INFO", ParseString(log.INFO))
}
