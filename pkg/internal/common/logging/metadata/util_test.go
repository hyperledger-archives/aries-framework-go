/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package metadata

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/logging/api"
	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {

	verifyLevelsNoError := func(expected api.Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
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

func TestParseLevelError(t *testing.T) {

	verifyLevelError := func(expected api.Level, levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError(api.DEBUG, "", "D", "DE BUG", ".")

}

func TestParseString(t *testing.T) {
	require.Equal(t, "CRITICAL", ParseString(api.CRITICAL))
	require.Equal(t, "ERROR", ParseString(api.ERROR))
	require.Equal(t, "WARNING", ParseString(api.WARNING))
	require.Equal(t, "DEBUG", ParseString(api.DEBUG))
	require.Equal(t, "INFO", ParseString(api.INFO))
}
