/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
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
				name:   "canonizing sample document with extra cached dummy context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(createContextCache("http://localhost:8652/dummy.jsonld", extraJSONLDContext)),
				},
			},
			{
				name:   "canonizing sample document with extra cached dummy context and cached document loader",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(createContextCache("http://localhost:8652/dummy.jsonld", extraJSONLDContext)),
					WithDocumentLoader(jsonld.NewCachingDocumentLoader()),
				},
			},
			{
				name:   "canonizing sample document with extra cached dummy context and non caching document loader",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(createContextCache("http://localhost:8652/dummy.jsonld", extraJSONLDContext)),
					WithDocumentLoader(jsonld.NewCachingDocumentLoader()),
				},
			},
			{
				name:   "canonizing sample document with extra byte cached dummy context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(map[string]interface{}{
						"http://localhost:8652/dummy.jsonld": []byte(extraJSONLDContext),
					}),
				},
			},
			{
				name:   "canonizing sample document with extra map cached dummy context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(map[string]interface{}{
						"http://localhost:8652/dummy.jsonld": stringToMap(t, extraJSONLDContext),
					}),
				},
			},
			{
				name:   "canonizing sample document with extra io.Reader cached dummy context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVP_extraContext,
				opts: []ProcessorOpts{
					WithRemoveAllInvalidRDF(), WithExternalContext("http://localhost:8652/dummy.jsonld"),
					WithDocumentLoaderCache(map[string]interface{}{
						"http://localhost:8652/dummy.jsonld": strings.NewReader(extraJSONLDContext),
					}),
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

				response, err := NewProcessor(defaultAlgorithm).GetCanonicalDocument(jsonldDoc,
					append([]ProcessorOpts{jsonldCache}, tc.opts...)...)
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
	loader := jsonld.NewCachingDocumentLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(inMemoryContext))
	if err != nil {
		panic(err)
	}

	loader.AddDocument(url, reader)

	return loader
}

func createContextCache(url, inMemoryContext string) map[string]interface{} {
	return map[string]interface{}{
		url: inMemoryContext,
	}
}

func stringToMap(t *testing.T, s string) map[string]interface{} {
	var m map[string]interface{}

	err := json.Unmarshal([]byte(s), &m)
	require.NoError(t, err)

	return m
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

//nolint:gochecknoglobals
var jsonldCache = WithDocumentLoaderCache(
	map[string]interface{}{
		"https://www.w3.org/2018/credentials/v1":                       vcDoc,
		"https://www.w3.org/2018/credentials/examples/v1":              vcExampleDoc,
		"https://www.w3.org/ns/odrl.jsonld":                            odrlDoc,
		"https://w3id.org/security/v1":                                 securityV1Doc,
		"https://w3id.org/security/v2":                                 securityV2Doc,
		"https://trustbloc.github.io/context/vc/credentials-v1.jsonld": trustblocDoc,
		"https://trustbloc.github.io/context/vc/examples-v1.jsonld":    trustblocExampleDoc,
	})

const vcDoc = `

{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "credentialSchema": {
          "@id": "cred:credentialSchema",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
          }
        },
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {
          "@id": "cred:refreshService",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "ManualRefreshService2018": "cred:ManualRefreshService2018"
          }
        },
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",

        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },

    "EcdsaSecp256k1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "EcdsaSecp256r1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "RsaSignature2018": {
      "@id": "https://w3id.org/security#RsaSignature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}
`

const vcExampleDoc = `
{
  "@context": [{
    "@version": 1.1
  },"https://www.w3.org/ns/odrl.jsonld", {
    "ex": "https://example.org/examples#",
    "schema": "http://schema.org/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",

    "3rdPartyCorrelation": "ex:3rdPartyCorrelation",
    "AllVerifiers": "ex:AllVerifiers",
    "Archival": "ex:Archival",
    "BachelorDegree": "ex:BachelorDegree",
    "Child": "ex:Child",
    "CLCredentialDefinition2019": "ex:CLCredentialDefinition2019",
    "CLSignature2019": "ex:CLSignature2019",
    "IssuerPolicy": "ex:IssuerPolicy",
    "HolderPolicy": "ex:HolderPolicy",
    "Mother": "ex:Mother",
    "RelationshipCredential": "ex:RelationshipCredential",
    "UniversityDegreeCredential": "ex:UniversityDegreeCredential",
    "ZkpExampleSchema2018": "ex:ZkpExampleSchema2018",

    "issuerData": "ex:issuerData",
    "attributes": "ex:attributes",
    "signature": "ex:signature",
    "signatureCorrectnessProof": "ex:signatureCorrectnessProof",
    "primaryProof": "ex:primaryProof",
    "nonRevocationProof": "ex:nonRevocationProof",

    "alumniOf": {"@id": "schema:alumniOf", "@type": "rdf:HTML"},
    "child": {"@id": "ex:child", "@type": "@id"},
    "degree": "ex:degree",
    "degreeType": "ex:degreeType",
    "degreeSchool": "ex:degreeSchool",
    "college": "ex:college",
    "name": {"@id": "schema:name", "@type": "rdf:HTML"},
    "givenName": "schema:givenName",
    "familyName": "schema:familyName",
    "parent": {"@id": "ex:parent", "@type": "@id"},
    "referenceId": "ex:referenceId",
    "documentPresence": "ex:documentPresence",
    "evidenceDocument": "ex:evidenceDocument",
    "spouse": "schema:spouse",
    "subjectPresence": "ex:subjectPresence",
    "verifier": {"@id": "ex:verifier", "@type": "@id"}
  }]
}
`

const odrlDoc = `
{
 "@context": {
    "odrl":    "http://www.w3.org/ns/odrl/2/",
    "rdf":     "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs":    "http://www.w3.org/2000/01/rdf-schema#",
    "owl":     "http://www.w3.org/2002/07/owl#",
    "skos":    "http://www.w3.org/2004/02/skos/core#",
    "dct":     "http://purl.org/dc/terms/",
    "xsd":     "http://www.w3.org/2001/XMLSchema#",
    "vcard":   "http://www.w3.org/2006/vcard/ns#",
    "foaf":    "http://xmlns.com/foaf/0.1/",
    "schema":  "http://schema.org/",
    "cc":      "http://creativecommons.org/ns#",

    "uid":     "@id",
    "type":    "@type",

    "Policy":           "odrl:Policy",
    "Rule":             "odrl:Rule",
    "profile":          {"@type": "@id", "@id": "odrl:profile"},

    "inheritFrom":      {"@type": "@id", "@id": "odrl:inheritFrom"},

    "ConflictTerm":     "odrl:ConflictTerm",
    "conflict":         {"@type": "@vocab", "@id": "odrl:conflict"},
    "perm":             "odrl:perm",
    "prohibit":         "odrl:prohibit",
    "invalid":          "odrl:invalid",

    "Agreement":           "odrl:Agreement",
    "Assertion":           "odrl:Assertion",
    "Offer":               "odrl:Offer",
    "Privacy":             "odrl:Privacy",
    "Request":             "odrl:Request",
    "Set":                 "odrl:Set",
    "Ticket":              "odrl:Ticket",

    "Asset":               "odrl:Asset",
    "AssetCollection":     "odrl:AssetCollection",
    "relation":            {"@type": "@id", "@id": "odrl:relation"},
    "hasPolicy":           {"@type": "@id", "@id": "odrl:hasPolicy"},

    "target":             {"@type": "@id", "@id": "odrl:target"},
    "output":             {"@type": "@id", "@id": "odrl:output"},

    "partOf":            {"@type": "@id", "@id": "odrl:partOf"},
	"source":            {"@type": "@id", "@id": "odrl:source"},

    "Party":              "odrl:Party",
    "PartyCollection":    "odrl:PartyCollection",
    "function":           {"@type": "@vocab", "@id": "odrl:function"},
    "PartyScope":         "odrl:PartyScope",

    "assignee":             {"@type": "@id", "@id": "odrl:assignee"},
    "assigner":             {"@type": "@id", "@id": "odrl:assigner"},
	"assigneeOf":           {"@type": "@id", "@id": "odrl:assigneeOf"},
    "assignerOf":           {"@type": "@id", "@id": "odrl:assignerOf"},
    "attributedParty":      {"@type": "@id", "@id": "odrl:attributedParty"},
	"attributingParty":     {"@type": "@id", "@id": "odrl:attributingParty"},
    "compensatedParty":     {"@type": "@id", "@id": "odrl:compensatedParty"},
    "compensatingParty":    {"@type": "@id", "@id": "odrl:compensatingParty"},
    "consentingParty":      {"@type": "@id", "@id": "odrl:consentingParty"},
	"consentedParty":       {"@type": "@id", "@id": "odrl:consentedParty"},
    "informedParty":        {"@type": "@id", "@id": "odrl:informedParty"},
	"informingParty":       {"@type": "@id", "@id": "odrl:informingParty"},
    "trackingParty":        {"@type": "@id", "@id": "odrl:trackingParty"},
	"trackedParty":         {"@type": "@id", "@id": "odrl:trackedParty"},
	"contractingParty":     {"@type": "@id", "@id": "odrl:contractingParty"},
	"contractedParty":      {"@type": "@id", "@id": "odrl:contractedParty"},

    "Action":                "odrl:Action",
    "action":                {"@type": "@vocab", "@id": "odrl:action"},
    "includedIn":            {"@type": "@id", "@id": "odrl:includedIn"},
    "implies":               {"@type": "@id", "@id": "odrl:implies"},

    "Permission":            "odrl:Permission",
    "permission":            {"@type": "@id", "@id": "odrl:permission"},

    "Prohibition":           "odrl:Prohibition",
    "prohibition":           {"@type": "@id", "@id": "odrl:prohibition"},

    "obligation":            {"@type": "@id", "@id": "odrl:obligation"},

    "use":                   "odrl:use",
    "grantUse":              "odrl:grantUse",
    "aggregate":             "odrl:aggregate",
    "annotate":              "odrl:annotate",
    "anonymize":             "odrl:anonymize",
    "archive":               "odrl:archive",
    "concurrentUse":         "odrl:concurrentUse",
    "derive":                "odrl:derive",
    "digitize":              "odrl:digitize",
    "display":               "odrl:display",
    "distribute":            "odrl:distribute",
    "execute":               "odrl:execute",
    "extract":               "odrl:extract",
    "give":                  "odrl:give",
    "index":                 "odrl:index",
    "install":               "odrl:install",
    "modify":                "odrl:modify",
    "move":                  "odrl:move",
    "play":                  "odrl:play",
    "present":               "odrl:present",
    "print":                 "odrl:print",
    "read":                  "odrl:read",
    "reproduce":             "odrl:reproduce",
    "sell":                  "odrl:sell",
    "stream":                "odrl:stream",
    "textToSpeech":          "odrl:textToSpeech",
    "transfer":              "odrl:transfer",
    "transform":             "odrl:transform",
    "translate":             "odrl:translate",

    "Duty":                 "odrl:Duty",
    "duty":                 {"@type": "@id", "@id": "odrl:duty"},
    "consequence":          {"@type": "@id", "@id": "odrl:consequence"},
	"remedy":               {"@type": "@id", "@id": "odrl:remedy"},

    "acceptTracking":       "odrl:acceptTracking",
    "attribute":            "odrl:attribute",
    "compensate":           "odrl:compensate",
    "delete":               "odrl:delete",
    "ensureExclusivity":    "odrl:ensureExclusivity",
    "include":              "odrl:include",
    "inform":               "odrl:inform",
    "nextPolicy":           "odrl:nextPolicy",
    "obtainConsent":        "odrl:obtainConsent",
    "reviewPolicy":         "odrl:reviewPolicy",
    "uninstall":            "odrl:uninstall",
    "watermark":            "odrl:watermark",

    "Constraint":           "odrl:Constraint",
	"LogicalConstraint":    "odrl:LogicalConstraint",
    "constraint":           {"@type": "@id", "@id": "odrl:constraint"},
	"refinement":           {"@type": "@id", "@id": "odrl:refinement"},
    "Operator":             "odrl:Operator",
    "operator":             {"@type": "@vocab", "@id": "odrl:operator"},
    "RightOperand":         "odrl:RightOperand",
    "rightOperand":         "odrl:rightOperand",
    "rightOperandReference":{"@type": "xsd:anyURI", "@id": "odrl:rightOperandReference"},
    "LeftOperand":          "odrl:LeftOperand",
    "leftOperand":          {"@type": "@vocab", "@id": "odrl:leftOperand"},
    "unit":                 "odrl:unit",
    "dataType":             {"@type": "xsd:anyType", "@id": "odrl:datatype"},
    "status":               "odrl:status",

    "absolutePosition":        "odrl:absolutePosition",
    "absoluteSpatialPosition": "odrl:absoluteSpatialPosition",
    "absoluteTemporalPosition":"odrl:absoluteTemporalPosition",
    "absoluteSize":            "odrl:absoluteSize",
    "count":                   "odrl:count",
    "dateTime":                "odrl:dateTime",
    "delayPeriod":             "odrl:delayPeriod",
    "deliveryChannel":         "odrl:deliveryChannel",
    "elapsedTime":             "odrl:elapsedTime",
    "event":                   "odrl:event",
    "fileFormat":              "odrl:fileFormat",
    "industry":                "odrl:industry:",
    "language":                "odrl:language",
    "media":                   "odrl:media",
    "meteredTime":             "odrl:meteredTime",
    "payAmount":               "odrl:payAmount",
    "percentage":              "odrl:percentage",
    "product":                 "odrl:product",
    "purpose":                 "odrl:purpose",
    "recipient":               "odrl:recipient",
    "relativePosition":        "odrl:relativePosition",
    "relativeSpatialPosition": "odrl:relativeSpatialPosition",
    "relativeTemporalPosition":"odrl:relativeTemporalPosition",
    "relativeSize":            "odrl:relativeSize",
    "resolution":              "odrl:resolution",
    "spatial":                 "odrl:spatial",
    "spatialCoordinates":      "odrl:spatialCoordinates",
    "systemDevice":            "odrl:systemDevice",
    "timeInterval":            "odrl:timeInterval",
    "unitOfCount":             "odrl:unitOfCount",
    "version":                 "odrl:version",
    "virtualLocation":         "odrl:virtualLocation",

    "eq":                   "odrl:eq",
    "gt":                   "odrl:gt",
    "gteq":                 "odrl:gteq",
    "lt":                   "odrl:lt",
    "lteq":                 "odrl:lteq",
    "neq":                  "odrl:neg",
    "isA":                  "odrl:isA",
    "hasPart":              "odrl:hasPart",
    "isPartOf":             "odrl:isPartOf",
    "isAllOf":              "odrl:isAllOf",
    "isAnyOf":              "odrl:isAnyOf",
    "isNoneOf":             "odrl:isNoneOf",
    "or":                   "odrl:or",
    "xone":                 "odrl:xone",
    "and":                  "odrl:and",
    "andSequence":          "odrl:andSequence",

    "policyUsage":                "odrl:policyUsage"

    }
}
`

const securityV1Doc = `
{
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "verificationMethod": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyWif": "sec:publicKeyWif",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
}`

const securityV2Doc = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256r1Signature2019": "sec:EcdsaSecp256r1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2019": "sec:EcdsaSecp256r1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}`

const trustblocDoc = `
{
  "@context": {
    "@version": 1.1,

    "id": "@id",
    "type": "@type",

    "trustbloc": "https://trustbloc.github.io/context#",
    "ldssk": "https://w3c-ccg.github.io/lds-jws2020/contexts/#",
    "sec": "https://w3id.org/security#",

    "publicKeyJwk": {
      "@id": "sec:publicKeyJwk",
      "@type": "@json"
    },

    "JsonWebSignature2020": {
      "@id": "https://w3c-ccg.github.io/lds-jws2020/contexts/#JsonWebSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    }
  }
}`

const trustblocExampleDoc = `
{
    "@context": {
      "@version": 1.1,

      "id": "@id",
      "type": "@type",

      "ex": "https://example.org/examples#",

      "image": {"@id": "http://schema.org/image", "@type": "@id"},

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

	framedView, err := processor.Frame(doc, frameDoc, jsonldCache)
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
	framedView, err = processor.Frame(doc, frameDoc, jsonldCache)
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
	framedView, err = processor.Frame(doc, frameDoc, jsonldCache)
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

func TestTransformBlankNodes(t *testing.T) {
	const (
		a  = "_:c14n0"
		ae = "<urn:bnid:_:c14n0>"
		b  = "_:c14n0 "
		be = "<urn:bnid:_:c14n0> "
		c  = "abcd _:c14n0 "
		ce = "abcd <urn:bnid:_:c14n0> "
		d  = "abcd _:c14n0 efgh"
		de = "abcd <urn:bnid:_:c14n0> efgh"
		e  = "abcd _:c14n23 efgh"
		ee = "abcd <urn:bnid:_:c14n23> efgh"
		f  = "abcd _:c14n efgh"
		fe = "abcd <urn:bnid:_:c14n> efgh"
		g  = ""
		ge = ""
	)

	at := TransformBlankNode(a)
	require.Equal(t, ae, at)

	bt := TransformBlankNode(b)
	require.Equal(t, be, bt)

	ct := TransformBlankNode(c)
	require.Equal(t, ce, ct)

	dt := TransformBlankNode(d)
	require.Equal(t, de, dt)

	et := TransformBlankNode(e)
	require.Equal(t, ee, et)

	ft := TransformBlankNode(f)
	require.Equal(t, fe, ft)

	gt := TransformBlankNode(g)
	require.Equal(t, ge, gt)
}
