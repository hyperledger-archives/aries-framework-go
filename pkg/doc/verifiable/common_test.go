/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestJwtAlgorithm_Jose(t *testing.T) {
	joseAlg, err := RS256.jose()
	require.NoError(t, err)
	require.Equal(t, jose.RS256, joseAlg)

	joseAlg, err = EdDSA.jose()
	require.NoError(t, err)
	require.Equal(t, jose.EdDSA, joseAlg)

	// not supported alg
	_, err = JWSAlgorithm(-1).jose()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
}
