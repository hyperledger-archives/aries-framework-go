/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestGetCanonicalDocument(t *testing.T) {
	t.Run("Test get canonical document", func(t *testing.T) {
		tests := []struct {
			name   string
			doc    string
			result string
			err    string
		}{
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLdWithIncorrectRDF,
				result: canonizedIncorrectRDF,
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLdSample1,
				result: canonizedIncorrectRDF,
			},
			{
				name:   "canonizing sample proof document",
				doc:    jsonLDProofSample,
				result: canonizedJsonLDProof,
			},
			{
				name:   "canonizing sample document with multiple incorrect RDFs",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP,
			},
			{
				name:   "canonizing sample document with incorrect RDFs causing node label miss match issue",
				doc:    invalidRDFMessingUpLabelPrefixCounter,
				result: canonizedSampleVP2,
			},
			{
				name:   "canonizing empty document",
				doc:    `{}`,
				result: "",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var jsonldDoc map[string]interface{}
				err := json.Unmarshal([]byte(tc.doc), &jsonldDoc)
				require.NoError(t, err)

				response, err := NewProcessor(defaultAlgorithm).GetCanonicalDocument(jsonldDoc)
				if tc.err != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.err)
					return
				}

				require.NoError(t, err)
				require.EqualValues(t, tc.result, string(response))
			})
		}
	})
}

func TestCompact(t *testing.T) {
	t.Run("Test json ld processor compact", func(t *testing.T) {
		doc := map[string]interface{}{
			"@id": "http://example.org/test#book",
			"http://example.org/vocab#contains": map[string]interface{}{
				"@id": "http://example.org/test#chapter",
			},
			"http://purl.org/dc/elements/1.1/title": "Title",
		}

		context := map[string]interface{}{
			"@context": map[string]interface{}{
				"dc": "http://purl.org/dc/elements/1.1/",
				"ex": "http://example.org/vocab#",
				"ex:contains": map[string]interface{}{
					"@type": "@id",
				},
			},
		}

		compactedDoc, err := Default().Compact(doc, context, ld.NewDefaultDocumentLoader(nil))
		if err != nil {
			log.Println("Error when compacting JSON-LD document:", err)
			return
		}

		require.NoError(t, err)
		require.NotEmpty(t, compactedDoc)
		require.Len(t, compactedDoc, 4)
	})
}

func TestUtilFunctions(t *testing.T) {
	t.Run("Test find line number", func(t *testing.T) {
		l, e := findLineNumber(fmt.Errorf("sample error"))
		require.Error(t, e)
		require.True(t, l < 0)
	})
	t.Run("Test validate view", func(t *testing.T) {
		view, err := NewProcessor("").validateView(canonizedJsonLDProof)
		require.NoError(t, err)
		require.Equal(t, view, canonizedJsonLDProof)
	})
}

const (
	jsonLdWithIncorrectRDF = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSchema": [],
  "credentialStatus": {
    "id": "http://issuer.vc.rest.example.com:8070/status/1",
    "type": "CredentialStatusList2017"
  },
  "credentialSubject": {
    "degree": {
      "degree": "MIT",
      "type": "BachelorDegree"
    },
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "id": "https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "issuer": {
    "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
    "name": "alice_f94db66c-be63-4f03-af10-4205d1f625e1"
  },
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ]
}
`
	jsonLdSample1 = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSchema": [],
  "credentialStatus": {
    "id": "http://issuer.vc.rest.example.com:8070/status/1"
  },
  "credentialSubject": {
    "degree": {
      "degree": "MIT",
      "type": "BachelorDegree"
    },
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "id": "https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "issuer": {
    "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
    "name": "alice_f94db66c-be63-4f03-af10-4205d1f625e1"
  },
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ]
}
`
	// nolint
	canonizedIncorrectRDF = `<did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg> <http://schema.org/name> "alice_f94db66c-be63-4f03-af10-4205d1f625e1"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#credentialStatus> <http://issuer.vc.rest.example.com:8070/status/1> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#issuanceDate> "2020-03-16T22:37:26.544Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#issuer> <did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n0 <https://example.org/examples#degree> "MIT" .
`
	// nolint
	jsonLDProofSample = `{
  "@context": "https://w3id.org/security/v2",
  "created": "2020-04-08T04:00:22Z",
  "proofPurpose": "assertionMethod",
  "type": "Ed25519Signature2018",
  "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
}`

	// nolint
	canonizedJsonLDProof = `_:c14n0 <http://purl.org/dc/terms/created> "2020-04-08T04:00:22Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo> .
`

	jsonLDMultipleInvalidRDFs = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSchema": [],
  "credentialStatus": {
    "id": "http://issuer.vc.rest.example.com:8070/status/1",
    "type": "CredentialStatusList2017"
  },
 "credentialStatus": {
    "id": "http://issuer.vc.rest.example.com:8070/status/1",
    "type": "CredentialStatusList2017"
  },
  "credentialSubject": {
    "degree": {
      "degree": "MIT",
      "type": "BachelorDegree"
    },
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "id": "https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "issuer": {
    "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
    "type": "alice_f94db66c-be63-4f03-af10-4205d1f625e1"
  },
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ]
}
`
	// nolint
	canonizedSampleVP = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#credentialStatus> <http://issuer.vc.rest.example.com:8070/status/1> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#issuanceDate> "2020-03-16T22:37:26.544Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.com/credentials/932236e0-966c-44cf-9342-236c0a2c77a7> <https://www.w3.org/2018/credentials#issuer> <did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n0 <https://example.org/examples#degree> "MIT" .
`
	// nolint
	invalidRDFMessingUpLabelPrefixCounter = `{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiablePresentation"
    ],
    "verifiableCredential": [
      {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "credentialSchema": [],
        "credentialStatus": {
          "id": "http://issuer.vc.rest.example.com:8070/status/1",
          "type": "CredentialStatusList2017"
        },
        "credentialSubject": {
          "degree": {
            "degree": "MIT",
            "type": "BachelorDegree"
          },
          "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "name": "Jayden Doe",
          "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
        },
        "id": "https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20",
        "issuanceDate": "2020-03-16T22:37:26.544Z",
        "issuer": {
          "id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
          "name": "alice_e64b24cf-2698-495e-9770-01554a1ce780"
        },
        "proof": {
          "created": "2020-04-14T01:15:33Z",
          "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PEhM4787FbnSu98Er_OKeFn1BDqbdw2DrNhdBQfUou6qgUdITLfsmfPkXtuXM_AbLtrPuWi_yy9y8zIGX0YGDA",
          "proofPurpose": "assertionMethod",
          "type": "Ed25519Signature2018",
          "verificationMethod": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"
        },
        "type": [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ]
      }
    ]
  }`

	// nolint
	canonizedSampleVP2 = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> _:c14n1 .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" _:c14n1 .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 _:c14n1 .
<did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd> <http://schema.org/name> "alice_e64b24cf-2698-495e-9770-01554a1ce780"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <https://w3id.org/security#proof> _:c14n4 _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <https://www.w3.org/2018/credentials#credentialStatus> <http://issuer.vc.rest.example.com:8070/status/1> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <https://www.w3.org/2018/credentials#issuanceDate> "2020-03-16T22:37:26.544Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n1 .
<https://example.com/credentials/296d1a51-5577-4570-ba14-a4664fe2ca20> <https://www.w3.org/2018/credentials#issuer> <did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd> _:c14n1 .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> _:c14n1 .
_:c14n0 <https://example.org/examples#degree> "MIT" _:c14n1 .
_:c14n2 <http://purl.org/dc/terms/created> "2020-04-14T01:15:33Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n4 .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Ed25519Signature2018> _:c14n4 .
_:c14n2 <https://w3id.org/security#jws> "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PEhM4787FbnSu98Er_OKeFn1BDqbdw2DrNhdBQfUou6qgUdITLfsmfPkXtuXM_AbLtrPuWi_yy9y8zIGX0YGDA" _:c14n4 .
_:c14n2 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n4 .
_:c14n2 <https://w3id.org/security#verificationMethod> <did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd> _:c14n4 .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiablePresentation> .
_:c14n3 <https://www.w3.org/2018/credentials#verifiableCredential> _:c14n1 .
`
)
