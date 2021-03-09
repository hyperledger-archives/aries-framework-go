/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_compactJSONLD(t *testing.T) {
	t.Run("Extended both basic VC and subject model", func(t *testing.T) {
		contextURL := "http://127.0.0.1?context=3"

		vcJSONTemplate := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    },
    {
      "id": "did:example:abcdef1234568",
      "name": "Alex"
    },
    {
      "id": "did:example:abcdef1234569",
      "name": "Justin"
    }
  ],
  "proof": [
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-10T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRag",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9d0Y"
    },
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-11T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRll",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9dZq"
    }
  ],
  "termsOfUse": [
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/4"
    },
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/5"
    }
  ]
}
`
		vc := fmt.Sprintf(vcJSONTemplate, contextURL)

		loader := CachingJSONLDLoader()
		addJSONLDCachedContextFromFile(loader,
			"http://127.0.0.1?context=3",
			"context3.jsonld")

		opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

		err := compactJSONLD(vc, opts, true)
		require.NoError(t, err)
	})

	t.Run("Extended basic VC model, credentialSubject is defined as string (ID only)", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is a string (i.e. ID is defined only).

		contextURL := "http://127.0.0.1?context=4"

		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

		loader := CachingJSONLDLoader()
		addJSONLDCachedContextFromFile(loader,
			"http://127.0.0.1?context=4",
			"context4.jsonld")

		opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

		err := compactJSONLD(vcJSON, opts, true)
		require.NoError(t, err)
	})
}

func Test_compactJSONLDWithExtraUndefinedFields(t *testing.T) {
	contextURL := "http://127.0.0.1?context=5"

	vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": ["VerifiableCredential", "CustomExt12"],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": {
    "id": "did:example:abcdef1234567",
    "name": "Jane Doe",
    "favoriteFood": "Papaya"
  }
}
`
	vc := fmt.Sprintf(vcJSONTemplate, contextURL)

	loader := CachingJSONLDLoader()
	addJSONLDCachedContextFromFile(loader,
		"http://127.0.0.1?context=5",
		"context5.jsonld")

	opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

	err := compactJSONLD(vc, opts, true)
	require.Error(t, err)
	require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
}

func Test_compactJSONLDWithExtraUndefinedSubjectFields(t *testing.T) {
	contextURL := "http://127.0.0.1?context=6"
	loader := CachingJSONLDLoader()
	addJSONLDCachedContextFromFile(loader,
		"http://127.0.0.1?context=6",
		"context6.jsonld")

	t.Run("Extended basic VC model, credentialSubject is defined as object - undefined fields present",
		func(t *testing.T) {
			// Use a different VC to verify the case when credentialSubject is an array.
			vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    }
  ]
}
`

			vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)
			opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

			err := compactJSONLD(vcJSON, opts, true)
			require.Error(t, err)
			require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		})

	t.Run("Extended basic VC model, credentialSubject is defined as array - undefined fields present", func(t *testing.T) {
		// Use a different VC to verify the case when credentialSubject is an array.
		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    }
  ]
}
`

		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)
		opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

		err := compactJSONLD(vcJSON, opts, true)
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
	})
}

func Test_compactJSONLD_WithExtraUndefinedFieldsInProof(t *testing.T) {
	vcJSONWithValidProof := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-10T21:35:35Z",
    "verificationMethod": "did:key:z6MkjRag",
    "proofPurpose": "assertionMethod",
    "jws": "eyJ..l9d0Y"
  }
}
`

	err := compactJSONLD(vcJSONWithValidProof, defaultOpts(), true)
	require.NoError(t, err)

	// "newProp" field is present in the proof
	vcJSONWithInvalidProof := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-10T21:35:35Z",
    "verificationMethod": "did:key:z6MkjRag",
    "proofPurpose": "assertionMethod",
    "jws": "eyJ..l9d0Y",
    "newProp": "foo"
  }
}`

	err = compactJSONLD(vcJSONWithInvalidProof, defaultOpts(), true)
	require.Error(t, err)
	require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
}

func Test_compactJSONLD_CornerErrorCases(t *testing.T) {
	t.Run("Invalid JSON input", func(t *testing.T) {
		err := compactJSONLD("not a json", defaultOpts(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "convert JSON-LD doc to map")
	})

	t.Run("JSON-LD compact error", func(t *testing.T) {
		vcJSONTemplate := `
{
  "@context": 777,
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`

		err := compactJSONLD(vcJSONTemplate, defaultOpts(), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "compact JSON-LD document")
	})
}

func defaultOpts() *jsonldCredentialOpts {
	return &jsonldCredentialOpts{jsonldDocumentLoader: CachingJSONLDLoader()}
}

// nolint:gochecknoglobals // needed to avoid Go compiler perf optimizations for benchmarks.
var MajorSink string

func Benchmark_compactJSONLD(b *testing.B) {
	var sink string

	b.Run("Extended both basic VC and subject model", func(b *testing.B) {
		contextURL := "http://127.0.0.1?context=3"

		vcJSONTemplate := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": [
    {
      "id": "did:example:abcdef1234567",
      "name": "Jane Doe",
      "favoriteFood": "Papaya"
    },
    {
      "id": "did:example:abcdef1234568",
      "name": "Alex"
    },
    {
      "id": "did:example:abcdef1234569",
      "name": "Justin"
    }
  ],
  "proof": [
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-10T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRag",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9d0Y"
    },
    {
      "type": "Ed25519Signature2018",
      "created": "2020-04-11T21:35:35Z",
      "verificationMethod": "did:key:z6MkjRll",
      "proofPurpose": "assertionMethod",
      "jws": "eyJ..l9dZq"
    }
  ],
  "termsOfUse": [
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/4"
    },
    {
      "type": [
        "IssuerPolicy",
        "HolderPolicy"
      ],
      "id": "http://example.com/policies/credential/5"
    }
  ]
}
`

		vc := fmt.Sprintf(vcJSONTemplate, contextURL)

		b.RunParallel(func(pb *testing.PB) {
			b.ResetTimer()

			for pb.Next() {
				loader := CachingJSONLDLoader()
				addJSONLDCachedContextFromFile(loader,
					"http://127.0.0.1?context=3",
					"context3.jsonld")

				opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

				err := compactJSONLD(vc, opts, true)
				require.NoError(b, err)

				sink = "basic_compact_test"
			}

			MajorSink = sink
		})
	})

	b.Run("Extended basic VC model, credentialSubject is defined as string (ID only)", func(b *testing.B) {
		// Use a different VC to verify the case when credentialSubject is a string (i.e. ID is defined only).

		contextURL := "http://127.0.0.1?context=4"

		vcJSONTemplate := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "%s"
  ],
  "id": "http://example.com/credentials/4643",
  "type": [
    "VerifiableCredential",
    "CustomExt12"
  ],
  "issuer": "https://example.com/issuers/14",
  "issuanceDate": "2018-02-24T05:28:04Z",
  "referenceNumber": 83294847,
  "credentialSubject": "did:example:abcdef1234567"
}
`
		vcJSON := fmt.Sprintf(vcJSONTemplate, contextURL)

		b.RunParallel(func(pb *testing.PB) {
			b.ResetTimer()

			for pb.Next() {
				loader := CachingJSONLDLoader()
				addJSONLDCachedContextFromFile(loader,
					"http://127.0.0.1?context=4",
					"context4.jsonld")

				opts := &jsonldCredentialOpts{jsonldDocumentLoader: loader}

				err := compactJSONLD(vcJSON, opts, true)
				require.NoError(b, err)

				sink = "extended_compact_test"
			}

			MajorSink = sink
		})
	})
}
