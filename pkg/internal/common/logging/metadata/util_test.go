/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package metadata

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {

	verifyLevelsNoError := func(expected Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(CRITICAL, "critical", "CRITICAL", "CriticAL")
	verifyLevelsNoError(ERROR, "error", "ERROR", "ErroR")
	verifyLevelsNoError(WARNING, "warning", "WARNING", "WarninG")
	verifyLevelsNoError(DEBUG, "debug", "DEBUG", "DebUg")
	verifyLevelsNoError(INFO, "info", "INFO", "iNFo")
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
	require.Equal(t, "CRITICAL", ParseString(CRITICAL))
	require.Equal(t, "ERROR", ParseString(ERROR))
	require.Equal(t, "WARNING", ParseString(WARNING))
	require.Equal(t, "DEBUG", ParseString(DEBUG))
	require.Equal(t, "INFO", ParseString(INFO))
}
