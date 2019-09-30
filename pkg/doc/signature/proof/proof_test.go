/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const proofValueBase64 = "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA"

func TestProof(t *testing.T) {
	p, err := NewProof(map[string]interface{}{
		"type":       "type",
		"creator":    "didID",
		"created":    "2018-03-15T00:00:00Z",
		"domain":     "abc.com",
		"nonce":      "",
		"proofValue": proofValueBase64,
	})
	require.NoError(t, err)

	// test proof
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	proofValueBytes, err := base64.RawURLEncoding.DecodeString(proofValueBase64)
	require.NoError(t, err)

	require.Equal(t, "type", p.Type)
	require.Equal(t, "didID", p.Creator)
	require.Equal(t, &created, p.Created)
	require.Equal(t, "abc.com", p.Domain)
	require.Equal(t, []byte(""), p.Nonce)
	require.Equal(t, proofValueBytes, p.ProofValue)
}

func TestInvalidProofValue(t *testing.T) {
	p, err := NewProof(map[string]interface{}{
		"type":       "Ed25519Signature2018",
		"creator":    "creator",
		"created":    "2011-09-23T20:21:34Z",
		"proofValue": "hello",
	})
	require.Error(t, err)

	require.Nil(t, p)
	require.Contains(t, err.Error(), "illegal base64 data")
}

func TestInvalidNonce(t *testing.T) {
	p, err := NewProof(map[string]interface{}{
		"type":       "Ed25519Signature2018",
		"creator":    "creator",
		"created":    "2011-09-23T20:21:34Z",
		"nonce":      "hello",
		"proofValue": proofValueBase64,
	})
	require.Error(t, err)

	require.Nil(t, p)
	require.Contains(t, err.Error(), "illegal base64 data")
}
