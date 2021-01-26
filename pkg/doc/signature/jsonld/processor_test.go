/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
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
			opts   []ProcessorOpts
		}{
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLdWithIncorrectRDF,
				result: canonizedIncorrectRDF_Filtered,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLdWithIncorrectRDF,
				result: canonizedIncorrectRDF,
				opts:   []ProcessorOpts{},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLdSample1,
				result: canonizedIncorrectRDF_Filtered,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLdSample1,
				result: canonizedIncorrectRDF_Filtered,
				opts:   []ProcessorOpts{},
			},
			{
				name:   "canonizing sample proof document",
				doc:    jsonLDProofSample,
				result: canonizedJsonLDProof,
			},
			{
				name:   "canonizing sample document with multiple incorrect RDFs 1",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_filtered,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with extra context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(),
					WithExternalContext("https://trustbloc.github.io/context/vc/examples-v1.jsonld"),
				},
			},
			{
				name:   "canonizing sample document with extra dummy context and in-memory document loader",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoader(createInMemoryDocumentLoader("http://localhost:8652/dummy.jsonld", extraJSONLDContext)),
				},
			},
			{
				name:   "canonizing sample document with multiple incorrect RDFs 3",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP,
			},
			{
				name:   "canonizing sample document with incorrect RDFs causing node label miss match issue (array type)",
				doc:    invalidRDFMessingUpLabelPrefixCounter,
				result: canonizedSampleVP2,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with incorrect RDFs causing node label miss match issue (string type)",
				doc:    invalidRDFMessingUpLabelPrefixCounterStringType,
				result: canonizedSampleVP2,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF11",
				doc:    jsonldWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDF_allfiltered,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context",
				doc:    jsonVCWithProperContexts,
				result: canonizedJSONCredential,
			},
			{
				name:   "canonizing sample VC document with proper proper context but remove all invalid RDF",
				doc:    jsonVCWithProperContexts,
				result: canonizedJSONCredential,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with improper context",
				doc:    jsonVCWithIncorrectContexts,
				result: canonizedJSONCredential_notfiltered,
				opts:   []ProcessorOpts{},
			},
			{
				name:   "canonizing sample VC document with improper context but remove all invalid RDF",
				doc:    jsonVCWithIncorrectContexts,
				result: canonizedJSONCredential_filtered,
				opts:   []ProcessorOpts{WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing empty document",
				doc:    `{}`,
				result: "",
			},
			{
				name:   "canonizing document with 1 incorrect RDF with validation option",
				doc:    jsonldWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDF_allfiltered,
				opts:   []ProcessorOpts{WithValidateRDF()},
				err:    ErrInvalidRDFFound.Error(),
			},
			{
				name:   "canonizing document with 1 incorrect RDF with validation & remove all invalid RDF option",
				doc:    jsonldWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDF_allfiltered,
				opts:   []ProcessorOpts{WithValidateRDF(), WithRemoveAllInvalidRDF()},
				err:    ErrInvalidRDFFound.Error(),
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var jsonldDoc map[string]interface{}
				err := json.Unmarshal([]byte(tc.doc), &jsonldDoc)
				require.NoError(t, err)

				response, err := NewProcessor(defaultAlgorithm).GetCanonicalDocument(jsonldDoc, tc.opts...)
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

		compactedDoc, err := Default().Compact(doc, context)
		if err != nil {
			log.Println("Error when compacting JSON-LD document:", err)
			return
		}

		require.NoError(t, err)
		require.NotEmpty(t, compactedDoc)
		require.Len(t, compactedDoc, 4)
	})
}

func createInMemoryDocumentLoader(url, inMemoryContext string) *ld.CachingDocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	reader, err := ld.DocumentFromReader(strings.NewReader(inMemoryContext))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(url, reader)

	return loader
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
<http://issuer.vc.rest.example.com:8070/status/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <CredentialStatusList2017> .
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
	canonizedIncorrectRDF_Filtered = `<did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg> <http://schema.org/name> "alice_f94db66c-be63-4f03-af10-4205d1f625e1"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
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
	canonizedSampleVP = `<did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <alice_f94db66c-be63-4f03-af10-4205d1f625e1> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<http://issuer.vc.rest.example.com:8070/status/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <CredentialStatusList2017> .
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
	canonizedSampleVP_extraContext = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<http://issuer.vc.rest.example.com:8070/status/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#CredentialStatusList2017> .
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
	canonizedSampleVP_filtered = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
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
	invalidRDFMessingUpLabelPrefixCounterStringType = `{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": "VerifiablePresentation",
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

// nolint
const jsonldWith2KnownInvalidRDFs = `{
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
    "credentialStatus": {"id": "http://issuer.vc.rest.example.com:8070/status/1", "type": "CredentialStatusList2017"},
    "credentialSubject": {
        "degree": {"degree": "MIT", "type": "BachelorDegree"},
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe",
        "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
    },
    "id": "https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837",
    "issuanceDate": "2020-03-16T22:37:26.544Z",
    "issuer": {
        "id": "did:trustbloc:testnet.trustbloc.local:EiCL0ikZX2MABHKc_ZVobGCXzbK_F1dVIFjczt8cOI_8Vg",
        "name": "myprofile_ud_unireg_p256_jws_1"
    },
    "proof": {
        "created": "2020-04-25T17:29:31Z",
        "jws": "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MEYCIQCdyY3CgjXLYdtPgxDiHDzHxlomakAzgvntBy_dJL-N8AIhAMmVyd3DIwVUBgAUhO9OFjtC-qp_-xYqNBnDQtoH1caw",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "did:trustbloc:testnet.trustbloc.local:EiCL0ikZX2MABHKc_ZVobGCXzbK_F1dVIFjczt8cOI_8Vg#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L0hhREZiSkE1WUMyVmdZY3diTmNDd2FKNjFsNWtzd1ZTMnVfaEUwYVBMc3M9"
    },
    "type": ["VerifiableCredential", "UniversityDegreeCredential"]
}`

// nolint
const canonizedIncorrectRDF_allfiltered = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n1 .
<did:trustbloc:testnet.trustbloc.local:EiCL0ikZX2MABHKc_ZVobGCXzbK_F1dVIFjczt8cOI_8Vg> <http://schema.org/name> "myprofile_ud_unireg_p256_jws_1"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <https://w3id.org/security#proof> _:c14n0 .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <https://www.w3.org/2018/credentials#credentialStatus> <http://issuer.vc.rest.example.com:8070/status/1> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <https://www.w3.org/2018/credentials#issuanceDate> "2020-03-16T22:37:26.544Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.com/credentials/979deefc-df53-4520-992f-73a88b9b6837> <https://www.w3.org/2018/credentials#issuer> <did:trustbloc:testnet.trustbloc.local:EiCL0ikZX2MABHKc_ZVobGCXzbK_F1dVIFjczt8cOI_8Vg> .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n1 <https://example.org/examples#degree> "MIT" .
`

// nolint
const jsonVCWithProperContexts = `{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1",
        "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
        "https://trustbloc.github.io/context/vc/credentials-v1.jsonld"
    ],
    "credentialStatus": {
        "id": "https://issuer-vcs.trustbloc.local/status/1",
        "type": "CredentialStatusList2017"
    },
    "credentialSubject": {
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "degree": {
                "degree": "MIT",
                "type": "BachelorDegree"
            },
            "name": "Jayden Doe",
            "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	},
    "id": "http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440",
    "issuanceDate": "2020-04-29T00:04:25.1025635Z",
    "issuer": {
        "id": "did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q",
        "name": "trustbloc-jsonwebsignature2020-ed25519"
    },
    "proof": {
        "created": "2020-04-29T00:04:29Z",
        "jws": "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PyBEIah5rLOUIkfa3bDkEccDPn6RD9iL2n9Hndwgionu5ZcghR3ekt-4UjBKIhU7VMNcggxOQGD1srAIFlCEBw",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L3lCQUJlV0RHakJicUQ3eTNUWTgwc2Nrb3FUR3V0VS1TSC1CRDF5aEM4RTA9"
    },
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ]
}`

// nolint
const jsonVCWithIncorrectContexts = `{
    "@context": [
        "https://www.w3.org/2018/credentials/v1", 
		"https://www.w3.org/2018/credentials/examples/v1"
    ],
    "credentialStatus": {
        "id": "https://issuer-vcs.trustbloc.local/status/1",
        "type": "CredentialStatusList2017"
    },
	"credentialSubject": {
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "degree": {
                "degree": "MIT",
                "type": "BachelorDegree"
            },
            "name": "Jayden Doe",
            "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	},
    "id": "http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440",
    "issuanceDate": "2020-04-29T00:04:25.1025635Z",
    "issuer": {
        "id": "did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q",
        "name": "trustbloc-jsonwebsignature2020-ed25519"
    },
    "proof": {
        "created": "2020-04-29T00:04:29Z",
        "jws": "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PyBEIah5rLOUIkfa3bDkEccDPn6RD9iL2n9Hndwgionu5ZcghR3ekt-4UjBKIhU7VMNcggxOQGD1srAIFlCEBw",
        "proofPurpose": "assertionMethod",
        "type": "JsonWebSignature2020",
        "verificationMethod": "did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L3lCQUJlV0RHakJicUQ3eTNUWTgwc2Nrb3FUR3V0VS1TSC1CRDF5aEM4RTA9"
    },
    "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
    ]
}`

// nolint
const canonizedJSONCredential = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> <http://schema.org/name> "trustbloc-jsonwebsignature2020-ed25519"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://w3id.org/security#proof> _:c14n2 .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialStatus> <https://issuer-vcs.trustbloc.local/status/1> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuanceDate> "2020-04-29T00:04:25.1025635Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuer> <did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> .
<https://issuer-vcs.trustbloc.local/status/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#CredentialStatusList2017> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n0 <https://example.org/examples#degree> "MIT" .
_:c14n1 <http://purl.org/dc/terms/created> "2020-04-29T00:04:29Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> _:c14n2 .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3c-ccg.github.io/lds-jws2020/contexts/#JsonWebSignature2020> _:c14n2 .
_:c14n1 <https://w3id.org/security#jws> "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PyBEIah5rLOUIkfa3bDkEccDPn6RD9iL2n9Hndwgionu5ZcghR3ekt-4UjBKIhU7VMNcggxOQGD1srAIFlCEBw" _:c14n2 .
_:c14n1 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> _:c14n2 .
_:c14n1 <https://w3id.org/security#verificationMethod> <did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q#bG9jYWwtbG9jazovL2N1c3RvbS9tYXN0ZXIva2V5L3lCQUJlV0RHakJicUQ3eTNUWTgwc2Nrb3FUR3V0VS1TSC1CRDF5aEM4RTA9> _:c14n2 .
`

// nolint
const canonizedJSONCredential_filtered = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n1 .
<did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> <http://schema.org/name> "trustbloc-jsonwebsignature2020-ed25519"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://w3id.org/security#proof> _:c14n0 .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialStatus> <https://issuer-vcs.trustbloc.local/status/1> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuanceDate> "2020-04-29T00:04:25.1025635Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuer> <did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n1 <https://example.org/examples#degree> "MIT" .
`

// nolint
const canonizedJSONCredential_notfiltered = `<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/name> "Jayden Doe"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <http://schema.org/spouse> "did:example:c276e12ec21ebfeb1f712ebc6f1" .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://example.org/examples#degree> _:c14n0 .
<did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> <http://schema.org/name> "trustbloc-jsonwebsignature2020-ed25519"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#HTML> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#UniversityDegreeCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://w3id.org/security#proof> _:c14n2 .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialStatus> <https://issuer-vcs.trustbloc.local/status/1> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuanceDate> "2020-04-29T00:04:25.1025635Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.com/8de063d1-9c00-4093-8dc9-262ff89e3440> <https://www.w3.org/2018/credentials#issuer> <did:trustbloc:testnet.trustbloc.local:EiCukr5lyAmPI0E2lDstNHcvqKhTpJzc_Ql1KQWYCJIB_Q> .
<https://issuer-vcs.trustbloc.local/status/1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <CredentialStatusList2017> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#BachelorDegree> .
_:c14n0 <https://example.org/examples#degree> "MIT" .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <JsonWebSignature2020> _:c14n2 .
`

const extraJSONLDContext = `
{
    "@context": {
      "@version": 1.1,
  
      "id": "@id",
      "type": "@type",
      
      "ex": "https://example.org/examples#",

      "CredentialStatusList2017": "ex:CredentialStatusList2017",
      "DocumentVerification": "ex:DocumentVerification",
      "SupportingActivity": "ex:SupportingActivity"
    }
}
`

func TestProcessor_Frame(t *testing.T) {
	processor := Default()

	var doc map[string]interface{}

	err := json.Unmarshal([]byte(jsonLdSample1), &doc)
	require.NoError(t, err)

	frameJSON := `
	{
	 "@context": [
	   "https://www.w3.org/2018/credentials/v1",
	   "https://www.w3.org/2018/credentials/examples/v1"
	 ],
	 "type": ["VerifiableCredential", "UniversityDegreeCredential"],
	 "credentialSubject": {
	   "@explicit": true,
	   "spouse": {}
	 }
	}
	`

	var frameDoc map[string]interface{}

	err = json.Unmarshal([]byte(frameJSON), &frameDoc)
	require.NoError(t, err)

	framedView, err := processor.Frame(doc, frameDoc)
	require.NoError(t, err)

	require.Equal(t, map[string]interface{}{
		"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
	}, framedView["credentialSubject"])

	// Use the same ID for issuer and credentialSubject
	issuerMap, ok := doc["issuer"].(map[string]interface{})
	require.True(t, ok)

	subjectMap, ok := doc["credentialSubject"].(map[string]interface{})
	require.True(t, ok)

	subjectMap["id"] = issuerMap["id"]
	framedView, err = processor.Frame(doc, frameDoc)
	require.NoError(t, err)

	require.Equal(t, map[string]interface{}{
		"id":     "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
	}, framedView["credentialSubject"])

	// Set several subjects, one with the same ID as issuer.
	doc["credentialSubject"] = []interface{}{
		subjectMap,
		map[string]interface{}{
			"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"name":   "Jayden Doe",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f2",
		},
	}
	framedView, err = processor.Frame(doc, frameDoc)
	require.NoError(t, err)

	require.Equal(t, []interface{}{
		map[string]interface{}{
			"id":     "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1",
		},
		map[string]interface{}{
			"id":     "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f2",
		},
	},
		framedView["credentialSubject"])
}
