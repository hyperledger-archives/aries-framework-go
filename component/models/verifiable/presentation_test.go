/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	_ "embed"
	"encoding/json"
	"testing"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	ldcontext "github.com/hyperledger/aries-framework-go/component/models/ld/context"
	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldtestutil "github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const validPresentation = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/58473",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu/issuers/14",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": "Example University"
      },
      "proof": {
        "type": "RsaSignature2018"
      }
    }
  ],
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
`

const presentationWithoutCredentials = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
`

const validPresentationWithCustomFields = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/context/vc/presentation-exchange-submission-v1.jsonld"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
   "type": [
        "VerifiablePresentation",
        "PresentationSubmission"
    ],
    "presentation_submission": {
        "descriptor_map": [
            {
                "id": "degree_input_1",
                "path": "$.verifiableCredential.[0]"
            },
            {
                "id": "citizenship_input_1",
                "path": "$.verifiableCredential.[1]"
            }
        ]
    },
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "http://example.edu/credentials/58473",
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu/issuers/14",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": "Example University"
      },
      "proof": {
        "type": "RsaSignature2018"
      }
    }
  ],
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
`

//go:embed testdata/validPresentationWithJWTVC.jsonld
var validPresentationWithJWTVC []byte //nolint:gochecknoglobals

//go:embed testdata/context/presentation_submission_v1.jsonld
var presentationSubmissionV1 []byte //nolint:gochecknoglobals

func TestParsePresentation(t *testing.T) {
	t.Run("creates a new Verifiable Presentation from JSON with valid structure", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation), WithPresStrictValidation())
		require.NoError(t, err)
		require.NotNil(t, vp)

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
		}, vp.Context)

		// check id
		require.Equal(t, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", vp.ID)

		// check type
		require.Equal(t, []string{"VerifiablePresentation"}, vp.Type)

		// check verifiableCredentials
		require.NotNil(t, vp.Credentials())
		require.Len(t, vp.Credentials(), 1)

		// check holder
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vp.Holder)
	})

	t.Run("creates a new Verifiable Presentation from valid JSON without credentials", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(presentationWithoutCredentials), WithPresStrictValidation())
		require.NoError(t, err)
		require.NotNil(t, vp)

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
		}, vp.Context)

		// check id
		require.Equal(t, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", vp.ID)

		// check type
		require.Equal(t, []string{"VerifiablePresentation"}, vp.Type)

		// check verifiableCredentials
		require.Nil(t, vp.Credentials())
		require.Empty(t, vp.Credentials())

		// check holder
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vp.Holder)

		// check rawPresentation
		rp, err := vp.raw()
		require.NoError(t, err)

		require.IsType(t, nil, rp.Credential)
	})

	t.Run("creates a new Verifiable Presentation with custom/additional fields", func(t *testing.T) {
		verify := func(t *testing.T, vp *Presentation) {
			require.Len(t, vp.CustomFields, 1)
			require.Len(t, vp.CustomFields["presentation_submission"], 1)
			submission, ok := vp.CustomFields["presentation_submission"].(map[string]interface{})
			require.True(t, ok)
			require.Len(t, submission, 1)
			descrMap, ok := submission["descriptor_map"].([]interface{})
			require.True(t, ok)
			require.Len(t, descrMap, 2)
		}

		loader := createTestDocumentLoader(t, ldcontext.Document{
			URL:     "https://trustbloc.github.io/context/vc/presentation-exchange-submission-v1.jsonld",
			Content: presentationSubmissionV1,
		})

		vp, err := ParsePresentation([]byte(validPresentationWithCustomFields), WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NotNil(t, vp)
		verify(t, vp)

		b, e := vp.MarshalJSON()
		require.NoError(t, e)
		require.NotEmpty(t, b)

		vp, err = ParsePresentation(b, WithPresStrictValidation(), WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NotNil(t, vp)
		verify(t, vp)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		vp, err := newTestPresentation(t, []byte(emptyJSONDoc))
		require.Error(t, err)
		require.Nil(t, vp)
	})

	t.Run("fails to create a new Verifiable Presentation from non-JSON doc", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte("non json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of verifiable presentation")
		require.Nil(t, vp)
	})

	t.Run("strict VP validation fails because of invalid field in VP", func(t *testing.T) {
		var vpMap map[string]interface{}

		err := json.Unmarshal([]byte(validPresentation), &vpMap)
		require.NoError(t, err)

		// add invalid field
		vpMap["foo1"] = "bar1"

		vpBytes, err := json.Marshal(vpMap)
		require.NoError(t, err)

		vp, err := newTestPresentation(t, vpBytes, WithPresStrictValidation())
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})

	t.Run("strict VP validation fails because of invalid field in VP proof", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation))
		require.NoError(t, err)

		signer, err := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, err)

		ss := ed25519signature2018.New(suite.WithSigner(signer),
			suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

		ldpContext := &LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureJWS,
			Suite:                   ss,
			VerificationMethod:      "did:example:123456#key1",
		}

		err = vp.AddLinkedDataProof(ldpContext, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
		require.NoError(t, err)

		proof := vp.Proofs[0]
		proof["foo2"] = "bar2"

		vpBytes, err := json.Marshal(vp)
		require.NoError(t, err)

		vp, err = newTestPresentation(t, vpBytes,
			WithPresStrictValidation(),
			WithPresPublicKeyFetcher(SingleKey(signer.PublicKeyBytes(), kms.ED25519)))
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})

	t.Run("strict VP validation fails because of invalid field in VC of VP", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation))
		require.NoError(t, err)

		vc := vp.Credentials()[0]
		require.NotNil(t, vc)

		vcMap, ok := vc.(map[string]interface{})
		require.True(t, ok)

		vcMap["foo3"] = "bar3"

		vpBytes, err := json.Marshal(vp)
		require.NoError(t, err)

		vp, err = newTestPresentation(t, vpBytes, WithPresStrictValidation())
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})

	t.Run("parsing VP with a JWT VC succeeds", func(t *testing.T) {
		loader := createTestDocumentLoader(t, ldcontext.Document{
			URL:     "https://trustbloc.github.io/context/vc/presentation-exchange-submission-v1.jsonld",
			Content: presentationSubmissionV1,
		})

		vp, err := ParsePresentation(validPresentationWithJWTVC, WithPresDisabledProofCheck(),
			WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NotNil(t, vp)
	})

	t.Run("parsing VP with a JWT VC with required JSON-LD checks succeeds", func(t *testing.T) {
		vp, err := ParsePresentation(validPresentationWithJWTVC, WithPresDisabledProofCheck(),
			WithDisabledJSONLDChecks())
		require.NoError(t, err)
		require.NotNil(t, vp)
	})
}

func TestValidateVP_Context(t *testing.T) {
	t.Run("rejects verifiable presentation with empty context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation with invalid context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = []string{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1",
		}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match: \"https://www.w3.org/2018/credentials/v1\"")
		require.Nil(t, vp)
	})

	t.Run("generate verifiable presentation with valid string context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = "https://www.w3.org/2018/credentials/v1"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.NoError(t, err)
		require.NotNil(t, vp)
	})

	t.Run("rejects verifiable presentation with invalid string context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = "https://www.w3.org/2018/credentials/v2"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match: \"https://www.w3.org/2018/credentials/v1\"")
		require.Nil(t, vp)
	})
}

func TestValidateVP_ID(t *testing.T) {
	t.Run("accept verifiable presentation with string ID", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.ID = "id"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = newTestPresentation(t, bytes)
		require.NoError(t, err)
	})
}

func TestValidateVP_Type(t *testing.T) {
	t.Run("accepts verifiable presentation with single VerifiablePresentation type", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "VerifiablePresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = newTestPresentation(t, bytes)
		require.NoError(t, err)
	})

	t.Run("accepts verifiable presentation with multiple types where VerifiablePresentation is a first type",
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"VerifiablePresentation", "CredentialManagerPresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = newTestPresentation(t, bytes)
			require.NoError(t, err)
		})

	t.Run("accepts verifiable presentation with multiple types where VerifiablePresentation is not a first type",
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"CredentialManagerPresentation", "VerifiablePresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = newTestPresentation(t, bytes)
			require.NoError(t, err)
		})

	t.Run("rejects verifiable presentation with no type defined", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "type is required")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation where single type is not VerifiablePresentation", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "CredentialManagerPresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Holder(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url holder", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Holder = "not valid presentation Holder URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(t, bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "holder: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestPresentation_MarshalJSON(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation))
	require.NoError(t, err)
	require.NotEmpty(t, vp)

	// convert verifiable credential to json byte data
	vpData, err := vp.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vpData)

	// convert json byte data back to verifiable presentation
	vp2, err := newTestPresentation(t, vpData)
	require.NoError(t, err)
	require.NotEmpty(t, vp2)

	// verify that verifiable presentations created by ParsePresentation() and MarshalJSON() matches
	require.Equal(t, vp, vp2)
}

func TestNewPresentation(t *testing.T) {
	r := require.New(t)

	vc, err := ParseCredential([]byte(validCredential),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())
	r.NoError(err)

	// Pass Credential struct pointer
	vp, err := NewPresentation(WithCredentials(vc))
	r.NoError(err)
	r.Len(vp.credentials, 1)
	r.Equal(vc, vp.credentials[0])

	vp.AddCredentials(&Credential{})
	r.Len(vp.credentials, 2)

	// Pass VC marshalled into unsecured JWT
	jwtClaims, err := vc.JWTClaims(true)
	r.NoError(err)

	jwt, err := jwtClaims.MarshalUnsecuredJWT()
	r.NoError(err)

	vp, err = NewPresentation(WithJWTCredentials(jwt))
	r.NoError(err)
	r.Len(vp.credentials, 1)
	// VC JWT is NOT converted to vc struct, it's kept as is
	r.Equal(jwt, vp.credentials[0])

	// set multiple credentials
	vp, err = NewPresentation(WithCredentials(vc, vc), WithJWTCredentials(jwt), WithCredentials(vc))
	r.NoError(err)
	r.Len(vp.credentials, 4)
	r.Equal(vc, vp.credentials[0])
	r.Equal(vc, vp.credentials[1])
	r.Equal(jwt, vp.credentials[2])
	r.Equal(vc, vp.credentials[3])

	// Error - pass unsupported type
	_, err = NewPresentation(WithJWTCredentials("notajwt"))
	r.Error(err)
	r.EqualError(err, "credential is not base64url encoded JWT")
}

func TestPresentation_decodeCredentials(t *testing.T) {
	r := require.New(t)

	signer, err := newCryptoSigner(kms.ED25519Type)
	r.NoError(err)

	vc, err := parseTestCredential(t, []byte(validCredential))
	r.NoError(err)

	jwtClaims, err := vc.JWTClaims(false)
	r.NoError(err)

	jws, err := jwtClaims.MarshalJWS(EdDSA, signer, "did:123#k1")
	r.NoError(err)

	// single credential - JWS
	opts := defaultPresentationOpts()
	opts.jsonldCredentialOpts.jsonldDocumentLoader = createTestDocumentLoader(t)
	opts.publicKeyFetcher = SingleKey(signer.PublicKeyBytes(), kms.ED25519)
	dCreds, err := decodeCredentials(jws, opts)
	r.NoError(err)
	r.Len(dCreds, 1)

	// no credential
	dCreds, err = decodeCredentials(nil, opts)
	r.NoError(err)
	r.Len(dCreds, 0)
	dCreds, err = decodeCredentials([]interface{}{}, opts)
	r.NoError(err)
	r.Len(dCreds, 0)

	// single credential - JWS decoding failed (e.g. to no public key fetcher available)
	opts.publicKeyFetcher = nil
	_, err = decodeCredentials(jws, opts)
	r.Error(err)
}

func TestWithPresPublicKeyFetcher(t *testing.T) {
	vpOpt := WithPresPublicKeyFetcher(SingleKey([]byte("test pubKey"), kms.ED25519))
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.NotNil(t, opts.publicKeyFetcher)
}

func TestWithPresEmbeddedSignatureSuites(t *testing.T) {
	ss := ed25519signature2018.New()

	vpOpt := WithPresEmbeddedSignatureSuites(ss)
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.Equal(t, []verifier.SignatureSuite{ss}, opts.ldpSuites)
}

func TestWithPresJSONLDDocumentLoader(t *testing.T) {
	documentLoader := jsonld.NewDefaultDocumentLoader(nil)
	presentationOpt := WithPresJSONLDDocumentLoader(documentLoader)
	require.NotNil(t, presentationOpt)

	opts := &presentationOpts{}
	presentationOpt(opts)
	require.Equal(t, documentLoader, opts.jsonldDocumentLoader)
}

func TestParseUnverifiedPresentation(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	// happy path
	vp, err := ParsePresentation([]byte(validPresentation), WithPresDisabledProofCheck(),
		WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)
	require.NotNil(t, vp)

	// delete the embedded proof and check the VP decoding once again
	var vpJSON map[string]interface{}

	err = json.Unmarshal([]byte(validPresentation), &vpJSON)
	require.NoError(t, err)
	delete(vpJSON, "proof")

	vpWithoutProofBytes, err := json.Marshal(vpJSON)
	require.NoError(t, err)

	vp, err = ParsePresentation(vpWithoutProofBytes, WithPresDisabledProofCheck(),
		WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err)
	require.NotNil(t, vp)

	// VP decoding error
	vp, err = ParsePresentation([]byte("invalid"), WithPresDisabledProofCheck(),
		WithPresJSONLDDocumentLoader(loader))
	require.Error(t, err)
	require.Nil(t, vp)
}
