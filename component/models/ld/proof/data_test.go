/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"crypto/sha512"
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
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

	normalizedDoc, err := CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions, testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// test error due to missing proof option
	delete(proofOptions, jsonldCreated)
	normalizedDoc, err = CreateVerifyHash(&mockSignatureSuite{}, doc, proofOptions, testutil.WithDocumentLoader(t))
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

	canonicalProofOptions, err := prepareCanonicalProofOptions(
		&mockSignatureSuite{}, proofOptions, testutil.WithDocumentLoader(t))

	require.NoError(t, err)
	require.NotEmpty(t, canonicalProofOptions)

	// test missing created
	delete(proofOptions, jsonldCreated)
	canonicalProofOptions, err = prepareCanonicalProofOptions(
		&mockSignatureSuite{}, proofOptions, testutil.WithDocumentLoader(t))

	require.NotNil(t, err)
	require.Nil(t, canonicalProofOptions)
	require.Contains(t, err.Error(), "created is missing")
}

func TestCreateVerifyData(t *testing.T) {
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	p := &Proof{
		Type:    "type",
		Created: afgotime.NewTime(created),
		Creator: "key1",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	p.SignatureRepresentation = SignatureProofValue
	normalizedDoc, err := CreateVerifyData(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	p.SignatureRepresentation = SignatureProofValue
	normalizedDoc, err = CreateVerifyData(
		&mockSignatureSuite{compactProof: true}, doc, p, testutil.WithDocumentLoader(t))

	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	p.SignatureRepresentation = SignatureJWS
	p.JWS = "jws header.."
	normalizedDoc, err = CreateVerifyData(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotEmpty(t, normalizedDoc)

	// unsupported signature representation
	p.SignatureRepresentation = SignatureRepresentation(-1)
	signature, err := CreateVerifyData(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported signature representation")
	require.Nil(t, signature)
}

type mockSignatureSuite struct {
	compactProof bool
}

// GetCanonicalDocument will return normalized/canonical version of the document.
func (s *mockSignatureSuite) GetCanonicalDocument(doc map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	return processor.Default().GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *mockSignatureSuite) GetDigest(doc []byte) []byte {
	digest := sha512.Sum512(doc)
	return digest[:]
}

func (s *mockSignatureSuite) CompactProof() bool {
	return s.compactProof
}

//go:embed testdata/valid_doc.jsonld
var validDoc string //nolint:gochecknoglobals

// from https://json-ld.org/test-suite/reports/#test_a5ebfe589bd62d1029790695808f8ff9
const test1 = `{
  "@id": "http://greggkellogg.net/foaf#me",
  "http://xmlns.com/foaf/0.1/name": "Gregg Kellogg"
}`

const test1Result = `<http://greggkellogg.net/foaf#me> <http://xmlns.com/foaf/0.1/name> "Gregg Kellogg" .
`
