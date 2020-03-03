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
		"type":               "type",
		"creator":            "didID",
		"verificationMethod": "did:example:123456#key1",
		"created":            "2018-03-15T00:00:00Z",
		"domain":             "abc.com",
		"nonce":              "",
		"proofValue":         proofValueBase64,
	})
	require.NoError(t, err)

	// test proof
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	proofValueBytes, err := base64.RawURLEncoding.DecodeString(proofValueBase64)
	require.NoError(t, err)

	require.Equal(t, "type", p.Type)
	require.Equal(t, "didID", p.Creator)
	require.Equal(t, "did:example:123456#key1", p.VerificationMethod)
	require.Equal(t, &created, p.Created)
	require.Equal(t, "abc.com", p.Domain)
	require.Equal(t, []byte(""), p.Nonce)
	require.Equal(t, proofValueBytes, p.ProofValue)
}

func TestInvalidProofValue(t *testing.T) {
	// invalid proof value
	p, err := NewProof(map[string]interface{}{
		"type":       "Ed25519Signature2018",
		"creator":    "creator",
		"created":    "2011-09-23T20:21:34Z",
		"proofValue": "hello",
	})
	require.Error(t, err)
	require.Nil(t, p)
	require.Contains(t, err.Error(), "illegal base64 data")

	// proof is not defined (neither "proofValue" nor "jws" is defined)
	p, err = NewProof(map[string]interface{}{
		"type":    "Ed25519Signature2018",
		"creator": "creator",
		"created": "2011-09-23T20:21:34Z",
	})
	require.Error(t, err)
	require.Nil(t, p)
	require.Contains(t, err.Error(), "signature is not defined")
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

func TestProof_JSONLdObject(t *testing.T) {
	r := require.New(t)

	proofValueBytes, err := base64.RawURLEncoding.DecodeString(proofValueBase64)
	r.NoError(err)

	nonceBase64, err := base64.RawURLEncoding.DecodeString("abc")
	r.NoError(err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	r.NoError(err)

	p := &Proof{
		Type:         "Ed25519Signature2018",
		Created:      &created,
		Creator:      "creator",
		ProofValue:   proofValueBytes,
		JWS:          "test.jws.value",
		ProofPurpose: "assertionMethod",
		Domain:       "internal",
		Nonce:        nonceBase64,
	}

	pJSONLd := p.JSONLdObject()
	r.Equal("Ed25519Signature2018", pJSONLd["type"])
	r.Equal("2018-03-15T00:00:00Z", pJSONLd["created"])
	r.Equal("creator", pJSONLd["creator"])
	r.Equal(proofValueBase64, pJSONLd["proofValue"])
	r.Equal("test.jws.value", pJSONLd["jws"])
	r.Equal("assertionMethod", pJSONLd["proofPurpose"])
	r.Equal("internal", pJSONLd["domain"])
	r.Equal("abc", pJSONLd["nonce"])
}

func TestProof_PublicKeyID(t *testing.T) {
	p := Proof{
		Creator:            "creator",
		VerificationMethod: "verification method",
	}

	publicKeyID, err := p.PublicKeyID()
	require.NoError(t, err)
	require.Equal(t, "verification method", publicKeyID)

	p.VerificationMethod = ""
	publicKeyID, err = p.PublicKeyID()
	require.NoError(t, err)
	require.Equal(t, "creator", publicKeyID)

	p.Creator = ""
	publicKeyID, err = p.PublicKeyID()
	require.Error(t, err)
	require.Empty(t, publicKeyID)
}
