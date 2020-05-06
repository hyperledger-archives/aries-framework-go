/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"crypto/sha512"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
)

func TestCreateVerifyHashAlgorithm(t *testing.T) {
	proofOptions := map[string]interface{}{
		"type":    "type",
		"creator": "key1",
		"created": "2018-03-15T00:00:00Z",
	}

	var doc map[string]interface{}
	err := json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	normalizedDoc, err := CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// test error due to missing proof option
	delete(proofOptions, jsonldCreated)
	normalizedDoc, err = CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions)
	require.NotNil(t, err)
	require.Nil(t, normalizedDoc)
	require.Contains(t, err.Error(), "created is missing")
}

func TestPrepareCanonicalDocument(t *testing.T) {
	var doc map[string]interface{}
	err := json.Unmarshal([]byte(test1), &doc)
	require.NoError(t, err)

	normalizedDoc, err := prepareCanonicalDocument(&mockSignatureSuite{}, doc)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)
	require.Equal(t, test1Result, string(normalizedDoc))
}

func TestPrepareCanonicalProofOptions(t *testing.T) {
	proofOptions := map[string]interface{}{
		"@context": []interface{}{"https://w3id.org/did/v1"},
		"type":     "type",
		"creator":  "key1",
		"created":  "2018-03-15T00:00:00Z",
		"domain":   "abc.com",
		"nonce":    "nonce",
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(&mockSignatureSuite{}, proofOptions)
	require.NoError(t, err)
	require.NotEmpty(t, canonicalProofOptions)

	// test missing created
	delete(proofOptions, jsonldCreated)
	canonicalProofOptions, err = prepareCanonicalProofOptions(&mockSignatureSuite{}, proofOptions)
	require.NotNil(t, err)
	require.Nil(t, canonicalProofOptions)
	require.Contains(t, err.Error(), "created is missing")
}

func TestCreateVerifyData(t *testing.T) {
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	p := &Proof{
		Type:    "type",
		Created: util.NewTime(created),
		Creator: "key1",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	p.SignatureRepresentation = SignatureProofValue
	normalizedDoc, err := CreateVerifyData(&mockSignatureSuite{}, doc, p)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	p.SignatureRepresentation = SignatureJWS
	p.JWS = "jws header.."
	normalizedDoc, err = CreateVerifyData(&mockSignatureSuite{}, doc, p)
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// unsupported signature representation
	p.SignatureRepresentation = SignatureRepresentation(-1)
	signature, err := CreateVerifyData(&mockSignatureSuite{}, doc, p)

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signature representation")
	require.Nil(t, signature)
}

type mockSignatureSuite struct {
	compactProof bool
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (s *mockSignatureSuite) GetCanonicalDocument(doc map[string]interface{},
	opts ...jsonld.ProcessorOpts) ([]byte, error) {
	return jsonld.Default().GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest
func (s *mockSignatureSuite) GetDigest(doc []byte) []byte {
	digest := sha512.Sum512(doc)
	return digest[:]
}

func (s *mockSignatureSuite) CompactProof() bool {
	return s.compactProof
}

//nolint:lll
const validDoc = `{
  "@context": ["https://w3id.org/did/v1"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "created": "2002-10-10T17:00:00Z"
}`

// from https://json-ld.org/test-suite/reports/#test_a5ebfe589bd62d1029790695808f8ff9
const test1 = `{
  "@id": "http://greggkellogg.net/foaf#me",
  "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg"
}`

const test1Result = `<http://greggkellogg.net/foaf#me> <http://xmlns.com/foaf/0.1/name> "Gregg Kellogg" .
`
