/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureSuite_GetCanonicalDocument(t *testing.T) {
	doc, err := New().GetCanonicalDocument(getDefaultDoc())
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, test28Result, string(doc))
}

func TestSignatureSuite_GetDigest(t *testing.T) {
	digest := New().GetDigest([]byte("test doc"))
	require.NotNil(t, digest)
}

func TestSignatureSuite_Accept(t *testing.T) {
	ss := New()
	accepted := ss.Accept("JsonWebSignature2020")
	require.True(t, accepted)

	accepted = ss.Accept("RsaSignature2018")
	require.False(t, accepted)
}

func getDefaultDoc() map[string]interface{} {
	// this JSON-LD document was taken from http://json-ld.org/test-suite/tests/toRdf-0028-in.jsonld
	doc := map[string]interface{}{
		"@context": map[string]interface{}{
			"sec":        "http://purl.org/security#",
			"xsd":        "http://www.w3.org/2001/XMLSchema#",
			"rdf":        "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
			"dc":         "http://purl.org/dc/terms/",
			"sec:signer": map[string]interface{}{"@type": "@id"},
			"dc:created": map[string]interface{}{"@type": "xsd:dateTime"},
		},
		"@id":                "http://example.org/sig1",
		"@type":              []interface{}{"rdf:Graph", "sec:SignedGraph"},
		"dc:created":         "2011-09-23T20:21:34Z",
		"sec:signer":         "http://payswarm.example.com/i/john/keys/5",
		"sec:signatureValue": "OGQzNGVkMzVm4NTIyZTkZDYMmMzQzNmExMgoYzI43Q3ODIyOWM32NjI=",
		"@graph": map[string]interface{}{
			"@id":      "http://example.org/fact1",
			"dc:title": "Hello World!",
		},
	}

	return doc
}

// taken from test 28 report https://json-ld.org/test-suite/reports/#test_30bc80ba056257df8a196e8f65c097fc

// nolint
const test28Result = `<http://example.org/fact1> <http://purl.org/dc/terms/title> "Hello World!" <http://example.org/sig1> .
<http://example.org/sig1> <http://purl.org/dc/terms/created> "2011-09-23T20:21:34Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/sig1> <http://purl.org/security#signatureValue> "OGQzNGVkMzVm4NTIyZTkZDYMmMzQzNmExMgoYzI43Q3ODIyOWM32NjI=" .
<http://example.org/sig1> <http://purl.org/security#signer> <http://payswarm.example.com/i/john/keys/5> .
<http://example.org/sig1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://purl.org/security#SignedGraph> .
<http://example.org/sig1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://www.w3.org/1999/02/22-rdf-syntax-ns#Graph> .
`
