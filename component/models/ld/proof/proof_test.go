/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"

	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
)

const (
	proofValueBase64    = "6mdES87erjP5r1qCSRW__otj-A_Rj0YgRO7XU_0Amhwdfa7AAmtGUSFGflR_fZqPYrY9ceLRVQCJ49s0q7-LBA"
	proofValueMultibase = "z5gpJQZoaLUXevXk2mYYbQE9krfaJYBBwQcJhhAvX3zs6daJ2Eb6VJoU46WkUYN8R1vgX7o8ktuUkzpRJS5aJRQyh"
)

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
	require.Equal(t, created, p.Created.Time)
	require.Equal(t, "abc.com", p.Domain)
	require.Equal(t, []byte(""), p.Nonce)
	require.Equal(t, proofValueBytes, p.ProofValue)

	// test proof with multibase encoding
	p, err = NewProof(map[string]interface{}{
		"type":               "Ed25519Signature2020",
		"creator":            "didID",
		"verificationMethod": "did:example:123456#key1",
		"created":            "2018-03-15T00:00:00Z",
		"domain":             "abc.com",
		"nonce":              "",
		"proofValue":         proofValueMultibase,
	})
	require.NoError(t, err)

	// test proof
	created, err = time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	_, proofValueBytes, err = multibase.Decode(proofValueMultibase)
	require.NoError(t, err)

	require.Equal(t, "Ed25519Signature2020", p.Type)
	require.Equal(t, "didID", p.Creator)
	require.Equal(t, "did:example:123456#key1", p.VerificationMethod)
	require.Equal(t, created, p.Created.Time)
	require.Equal(t, "abc.com", p.Domain)
	require.Equal(t, []byte(""), p.Nonce)
	require.Equal(t, proofValueBytes, p.ProofValue)

	// test created time with milliseconds section
	p, err = NewProof(map[string]interface{}{
		"type":               "type",
		"creator":            "didID",
		"verificationMethod": "did:example:123456#key1",
		"created":            "2018-03-15T00:00:00.972Z",
		"domain":             "abc.com",
		"nonce":              "",
		"proofValue":         proofValueBase64,
	})
	require.NoError(t, err)

	created, err = time.Parse(time.RFC3339Nano, "2018-03-15T00:00:00.972Z")
	require.NoError(t, err)
	require.Equal(t, created, p.Created.Time)

	// test created time with zero milliseconds section
	p, err = NewProof(map[string]interface{}{
		"type":               "type",
		"creator":            "didID",
		"verificationMethod": "did:example:123456#key1",
		"created":            "2018-03-15T00:00:00.00000Z",
		"domain":             "abc.com",
		"nonce":              "",
		"proofValue":         proofValueBase64,
	})
	require.NoError(t, err)

	require.NoError(t, err)
	require.Equal(t, "2018-03-15T00:00:00.00000Z", p.Created.FormatToString())

	t.Run("capabilityChain", func(t *testing.T) {
		t.Run("parses capabilityChain", func(t *testing.T) {
			cap1 := "http://edv.com/zcaps/1"
			cap2 := "http://edv.com/zcaps/2"
			p, err := NewProof(map[string]interface{}{
				"type":               "type",
				"creator":            "didID",
				"verificationMethod": "did:example:123456#key1",
				"created":            "2018-03-15T00:00:00Z",
				"domain":             "abc.com",
				"nonce":              "",
				"proofValue":         proofValueBase64,
				"capabilityChain":    []interface{}{cap1, cap2},
			})
			require.NoError(t, err)
			require.Equal(t, []interface{}{cap1, cap2}, p.CapabilityChain)
		})

		t.Run("no capabiltyChain", func(t *testing.T) {
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
			require.Empty(t, p.CapabilityChain)
		})

		t.Run("fails if capability chain is not an []interface{}", func(t *testing.T) {
			_, err := NewProof(map[string]interface{}{
				"type":               "type",
				"creator":            "didID",
				"verificationMethod": "did:example:123456#key1",
				"created":            "2018-03-15T00:00:00Z",
				"domain":             "abc.com",
				"nonce":              "",
				"proofValue":         proofValueBase64,
				"capabilityChain":    "INVALID FORMAT",
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid format for capabilityChain")
		})
	})
}

func TestInvalidInterfaceTypeShouldNotPanic(t *testing.T) {
	t.Run("does not panic if type is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               123,
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if created is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            123,
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing time")
	})

	t.Run("does not panic if creator is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            123,
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if verificationMethod is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": 123,
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if proofValue is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         123,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature is not defined")
	})

	t.Run("does not panic if jws is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"jws":                123,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature is not defined")
	})

	t.Run("does not panic if proofPurpose is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
			"proofPurpose":       123,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if domain is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             123,
			"nonce":              "",
			"proofValue":         proofValueBase64,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if nonce is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              123,
			"proofValue":         proofValueBase64,
		})
		require.NoError(t, err)
	})

	t.Run("does not panic if challenge is not a string", func(t *testing.T) {
		defer func() {
			r := recover()
			require.Nil(t, r)
		}()
		_, err := NewProof(map[string]interface{}{
			"type":               "type",
			"creator":            "didID",
			"verificationMethod": "did:example:123456#key1",
			"created":            "2018-03-15T00:00:00Z",
			"domain":             "abc.com",
			"nonce":              "",
			"proofValue":         proofValueBase64,
			"challenge":          123,
		})
		require.NoError(t, err)
	})
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
	require.EqualError(t, err, "unsupported encoding")

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
	require.Contains(t, err.Error(), "unsupported encoding")
}

func TestProof_JSONLdObject(t *testing.T) {
	r := require.New(t)

	_, proofValueBytes, err := multibase.Decode(proofValueMultibase)
	r.NoError(err)

	nonceBase64, err := base64.RawURLEncoding.DecodeString("abc")
	r.NoError(err)

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	r.NoError(err)

	p := &Proof{
		Type:         "Ed25519Signature2020",
		Created:      afgotime.NewTime(created),
		Creator:      "creator",
		ProofValue:   proofValueBytes,
		JWS:          "test.jws.value",
		ProofPurpose: "assertionMethod",
		Domain:       "internal",
		Nonce:        nonceBase64,
		Challenge:    "sample-challenge-xyz",
	}

	pJSONLd := p.JSONLdObject()
	r.Equal("Ed25519Signature2020", pJSONLd["type"])
	r.Equal("2018-03-15T00:00:00Z", pJSONLd["created"])
	r.Equal("creator", pJSONLd["creator"])
	r.Equal(proofValueMultibase, pJSONLd["proofValue"])
	r.Equal("test.jws.value", pJSONLd["jws"])
	r.Equal("assertionMethod", pJSONLd["proofPurpose"])
	r.Equal("internal", pJSONLd["domain"])
	r.Equal("abc", pJSONLd["nonce"])
	r.Equal("sample-challenge-xyz", pJSONLd["challenge"])

	// test created time with milliseconds section
	created, err = time.Parse(time.RFC3339Nano, "2018-03-15T00:00:00.972Z")
	require.NoError(t, err)

	p.Created = afgotime.NewTime(created)
	pJSONLd = p.JSONLdObject()
	r.Equal("2018-03-15T00:00:00.972Z", pJSONLd["created"])

	// test created time with zero milliseconds section
	created, err = time.Parse(time.RFC3339Nano, "2018-03-15T00:00:00.000Z")
	require.NoError(t, err)

	p.Created, err = afgotime.ParseTimeWrapper("2018-03-15T00:00:00.000Z")
	require.NoError(t, err)

	pJSONLd = p.JSONLdObject()
	r.Equal("2018-03-15T00:00:00.000Z", pJSONLd["created"])

	t.Run("capabilityChain", func(t *testing.T) {
		t.Run("included", func(t *testing.T) {
			capability := "http://edv.com/foo/zcaps/1"
			p := &Proof{
				Type:            "Ed25519Signature2018",
				Created:         afgotime.NewTime(created),
				Creator:         "creator",
				ProofValue:      proofValueBytes,
				JWS:             "test.jws.value",
				ProofPurpose:    "assertionMethod",
				Domain:          "internal",
				Nonce:           nonceBase64,
				Challenge:       "sample-challenge-xyz",
				CapabilityChain: []interface{}{capability},
			}
			result := p.JSONLdObject()
			r.Contains(result, "capabilityChain")
			chain, ok := result["capabilityChain"].([]interface{})
			r.True(ok)
			r.Len(chain, 1)
			r.Equal(capability, chain[0])
		})

		t.Run("not included", func(t *testing.T) {
			p := &Proof{
				Type:         "Ed25519Signature2018",
				Created:      afgotime.NewTime(created),
				Creator:      "creator",
				ProofValue:   proofValueBytes,
				JWS:          "test.jws.value",
				ProofPurpose: "assertionMethod",
				Domain:       "internal",
				Nonce:        nonceBase64,
				Challenge:    "sample-challenge-xyz",
			}
			result := p.JSONLdObject()
			r.NotContains(result, "capabilityChain")
		})
	})
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
