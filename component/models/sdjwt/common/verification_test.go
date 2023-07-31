/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	afjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

func TestVerifySigningAlgorithm(t *testing.T) {
	r := require.New(t)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := VerifySigningAlg(headers, []string{"EdDSA"})
		r.NoError(err)
	})

	t.Run("error - signing algorithm can not be empty", func(t *testing.T) {
		headers := make(afjose.Headers)
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "missing alg")
	})

	t.Run("success - EdDSA signing algorithm not in allowed list", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - signing algorithm can not be none", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "none"
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg value cannot be 'none'")
	})
}
