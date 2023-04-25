/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor_test

import (
	_ "embed"
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/require"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
)

const defaultAlgorithm = "URDNA2015"

func TestGetCanonicalDocument(t *testing.T) {
	loader, err := testutil.DocumentLoader(ldcontext.Document{
		URL:     "http://localhost:8652/dummy.jsonld",
		Content: extraJSONLDContext,
	})
	require.NoError(t, err)

	t.Run("Test get canonical document", func(t *testing.T) {
		tests := []struct {
			name   string
			doc    string
			result string
			err    string
			opts   []processor.Opts
		}{
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLDWithIncorrectRDF,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLDWithIncorrectRDF,
				result: canonizedIncorrectRDF,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLDSample1,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLDSample1,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing sample proof document",
				doc:    jsonLDProofSample,
				result: canonizedJSONLDProof,
			},
			{
				name:   "canonizing sample document with multiple incorrect RDFs 1",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with extra context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPExtraContext,
				opts: []processor.Opts{
					processor.WithRemoveAllInvalidRDF(),
					processor.WithExternalContext("https://trustbloc.github.io/context/vc/examples-v1.jsonld"),
				},
			},
			{
				name:   "canonizing sample document with extra dummy context and in-memory document loader",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPExtraContext,
				opts: []processor.Opts{
					processor.WithRemoveAllInvalidRDF(),
					processor.WithExternalContext("http://localhost:8652/dummy.jsonld"),
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
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with incorrect RDFs causing node label miss match issue (string type)",
				doc:    invalidRDFMessingUpLabelPrefixCounterString,
				result: canonizedSampleVP2,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF11",
				doc:    jsonLDWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDFAllFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context",
				doc:    vcWithProperContexts,
				result: canonizedJSONCredential,
			},
			{
				name:   "canonizing sample VC document with proper context but remove all invalid RDF",
				doc:    vcWithProperContexts,
				result: canonizedJSONCredential,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context 2",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
			},
			{
				name:   "canonizing sample VC document with proper context 2 but remove all invalid RDF",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context 2 with in-memory document loader",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
				opts:   []processor.Opts{processor.WithDocumentLoader(loader)},
			},
			{
				name:   "canonizing sample VC document with improper context",
				doc:    vcWithIncorrectContexts,
				result: canonizedJSONCredentialNotFiltered,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing sample VC document with improper context but remove all invalid RDF",
				doc:    vcWithIncorrectContexts,
				result: canonizedJSONCredentialFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing empty document",
				doc:    `{}`,
				result: "",
			},
			{
				name:   "canonizing document with 1 incorrect RDF with validation option",
				doc:    jsonLDWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDFAllFiltered,
				opts:   []processor.Opts{processor.WithValidateRDF()},
				err:    processor.ErrInvalidRDFFound.Error(),
			},
			{
				name:   "canonizing document with 1 incorrect RDF with validation & remove all invalid RDF option",
				doc:    jsonLDWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDFAllFiltered,
				opts:   []processor.Opts{processor.WithValidateRDF(), processor.WithRemoveAllInvalidRDF()},
				err:    processor.ErrInvalidRDFFound.Error(),
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				var jsonldDoc map[string]interface{}
				err := json.Unmarshal([]byte(tc.doc), &jsonldDoc)
				require.NoError(t, err)

				response, err := processor.NewProcessor(defaultAlgorithm).GetCanonicalDocument(jsonldDoc,
					append([]processor.Opts{processor.WithDocumentLoader(loader)}, tc.opts...)...)
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

		compactedDoc, err := processor.Default().Compact(doc, context)
		if err != nil {
			log.Println("Error when compacting JSON-LD document:", err)
			return
		}

		require.NoError(t, err)
		require.NotEmpty(t, compactedDoc)
		require.Len(t, compactedDoc, 4)
	})
}

func TestProcessor_Frame(t *testing.T) {
	processor := processor.Default()

	var doc map[string]interface{}

	err := json.Unmarshal([]byte(jsonLDSample1), &doc)
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
	}`

	var frameDoc map[string]interface{}

	err = json.Unmarshal([]byte(frameJSON), &frameDoc)
	require.NoError(t, err)

	framedView, err := processor.Frame(doc, frameDoc, testutil.WithDocumentLoader(t))
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
	framedView, err = processor.Frame(doc, frameDoc, testutil.WithDocumentLoader(t))
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

	// clear the ID, to test empty-ID handling
	doc["id"] = ""

	framedView, err = processor.Frame(doc, frameDoc, testutil.WithDocumentLoader(t))
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

	at := processor.TransformBlankNode(a)
	require.Equal(t, ae, at)

	bt := processor.TransformBlankNode(b)
	require.Equal(t, be, bt)

	ct := processor.TransformBlankNode(c)
	require.Equal(t, ce, ct)

	dt := processor.TransformBlankNode(d)
	require.Equal(t, de, dt)

	et := processor.TransformBlankNode(e)
	require.Equal(t, ee, et)

	ft := processor.TransformBlankNode(f)
	require.Equal(t, fe, ft)

	gt := processor.TransformBlankNode(g)
	require.Equal(t, ge, gt)
}

func BenchmarkGetCanonicalDocument(b *testing.B) {
	loader, err := testutil.DocumentLoader(ldcontext.Document{
		URL:     "http://localhost:8652/dummy.jsonld",
		Content: extraJSONLDContext,
	})
	require.NoError(b, err)

	b.Run("Benchmark get canonical document", func(b *testing.B) {
		tests := []struct {
			name   string
			doc    string
			result string
			opts   []processor.Opts
		}{
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLDWithIncorrectRDF,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF",
				doc:    jsonLDWithIncorrectRDF,
				result: canonizedIncorrectRDF,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLDSample1,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing valid document 1",
				doc:    jsonLDSample1,
				result: canonizedIncorrectRDFFiltered,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing sample proof document",
				doc:    jsonLDProofSample,
				result: canonizedJSONLDProof,
			},
			{
				name:   "canonizing sample document with multiple incorrect RDFs 1",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with extra context",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPExtraContext,
				opts: []processor.Opts{
					processor.WithRemoveAllInvalidRDF(),
					processor.WithExternalContext("https://trustbloc.github.io/context/vc/examples-v1.jsonld"),
				},
			},
			{
				name:   "canonizing sample document with extra dummy context and in-memory document loader",
				doc:    jsonLDMultipleInvalidRDFs,
				result: canonizedSampleVPExtraContext,
				opts: []processor.Opts{
					processor.WithRemoveAllInvalidRDF(),
					processor.WithExternalContext("http://localhost:8652/dummy.jsonld"),
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
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample document with incorrect RDFs causing node label miss match issue (string type)",
				doc:    invalidRDFMessingUpLabelPrefixCounterString,
				result: canonizedSampleVP2,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing document with 1 incorrect RDF11",
				doc:    jsonLDWith2KnownInvalidRDFs,
				result: canonizedIncorrectRDFAllFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context",
				doc:    vcWithProperContexts,
				result: canonizedJSONCredential,
			},
			{
				name:   "canonizing sample VC document with proper context but remove all invalid RDF",
				doc:    vcWithProperContexts,
				result: canonizedJSONCredential,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context 2",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
			},
			{
				name:   "canonizing sample VC document with proper context 2 but remove all invalid RDF",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing sample VC document with proper context 2 with in-memory document loader",
				doc:    vcWithProperContexts2,
				result: canonizedJSONCredential2,
				opts:   []processor.Opts{processor.WithDocumentLoader(loader)},
			},
			{
				name:   "canonizing sample VC document with improper context",
				doc:    vcWithIncorrectContexts,
				result: canonizedJSONCredentialNotFiltered,
				opts:   []processor.Opts{},
			},
			{
				name:   "canonizing sample VC document with improper context but remove all invalid RDF",
				doc:    vcWithIncorrectContexts,
				result: canonizedJSONCredentialFiltered,
				opts:   []processor.Opts{processor.WithRemoveAllInvalidRDF()},
			},
			{
				name:   "canonizing empty document",
				doc:    `{}`,
				result: "",
			},
		}

		for _, test := range tests {
			tc := test
			var sink string
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					var jsonldDoc map[string]interface{}
					err := json.Unmarshal([]byte(tc.doc), &jsonldDoc)
					require.NoError(b, err)

					response, err := processor.NewProcessor(defaultAlgorithm).GetCanonicalDocument(jsonldDoc,
						append([]processor.Opts{processor.WithDocumentLoader(loader)}, tc.opts...)...)
					require.NoError(b, err)
					require.EqualValues(b, tc.result, string(response))
				}
				sink = tc.result
			})

			MajorSink = sink
		}
	})
}

// nolint:gochecknoglobals // needed to avoid Go compiler perf optimizations for benchmarks (avoid optimize loop body).
var MajorSink string

//go:embed testdata/contexts/extra_jsonld_context.jsonld
var extraJSONLDContext []byte //nolint:gochecknoglobals // embedded extra test context

// nolint:gochecknoglobals // embedded test data
var (
	//go:embed testdata/canonized_incorrect_rdf.nq
	canonizedIncorrectRDF string
	//go:embed testdata/canonized_incorrect_rdf_all_filtered.nq
	canonizedIncorrectRDFAllFiltered string
	//go:embed testdata/canonized_incorrect_rdf_filtered.nq
	canonizedIncorrectRDFFiltered string
	//go:embed testdata/canonized_json_credential.nq
	canonizedJSONCredential string
	//go:embed testdata/canonized_json_credential_2.nq
	canonizedJSONCredential2 string
	//go:embed testdata/canonized_json_credential_filtered.nq
	canonizedJSONCredentialFiltered string
	//go:embed testdata/canonized_json_credential_not_filtered.nq
	canonizedJSONCredentialNotFiltered string
	//go:embed testdata/canonized_jsonld_proof.nq
	canonizedJSONLDProof string
	//go:embed testdata/canonized_sample_vp.nq
	canonizedSampleVP string
	//go:embed testdata/canonized_sample_vp_2.nq
	canonizedSampleVP2 string
	//go:embed testdata/canonized_sample_vp_extra_context.nq
	canonizedSampleVPExtraContext string
	//go:embed testdata/canonized_sample_vp_filtered.nq
	canonizedSampleVPFiltered string

	//go:embed testdata/invalid_rdf_messing_up_label_prefix_counter.jsonld
	invalidRDFMessingUpLabelPrefixCounter string
	//go:embed testdata/invalid_rdf_messing_up_label_prefix_counter_str.jsonld
	invalidRDFMessingUpLabelPrefixCounterString string

	//go:embed testdata/jsonld_multiple_invalid_rdfs.jsonld
	jsonLDMultipleInvalidRDFs string
	//go:embed testdata/jsonld_proof_sample.jsonld
	jsonLDProofSample string
	//go:embed testdata/jsonld_sample_1.jsonld
	jsonLDSample1 string
	//go:embed testdata/jsonld_with_2_known_invalid_rdfs.jsonld
	jsonLDWith2KnownInvalidRDFs string
	//go:embed testdata/jsonld_with_incorrect_rdf.jsonld
	jsonLDWithIncorrectRDF string
	//go:embed testdata/vc_with_incorrect_contexts.jsonld

	vcWithIncorrectContexts string
	//go:embed testdata/vc_with_proper_contexts.jsonld
	vcWithProperContexts string
	//go:embed testdata/vc_with_proper_contexts_2.jsonld
	vcWithProperContexts2 string
)
