/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

//nolint:lll
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
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-01-21T16:44:53+02:00",
    "proofValue": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78"
  }
}
`

//nolint:lll
const validEmptyPresentation = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": "VerifiablePresentation",
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-01-21T16:44:53+02:00",
    "proofValue": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78"
  }
}
`

func TestParsePresentation(t *testing.T) {
	t.Run("creates a new Verifiable Presentation from JSON with valid structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validPresentation), WithPresStrictValidation())
		require.NoError(t, err)
		require.NotNil(t, vp)

		// validate @context
		require.Equal(t, []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
			"https://trustbloc.github.io/context/vc/examples-v1.jsonld"}, vp.Context)

		// check id
		require.Equal(t, "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5", vp.ID)

		// check type
		require.Equal(t, []string{"VerifiablePresentation"}, vp.Type)

		// check verifiableCredentials
		require.NotNil(t, vp.Credentials())
		require.Len(t, vp.Credentials(), 1)

		// check holder
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vp.Holder)

		// check proof
		require.NotNil(t, vp.Proofs)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid empty VC structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validEmptyPresentation), WithPresStrictValidation(), WithPresRequireVC())
		require.Error(t, err)
		require.Nil(t, vp)
	})

	t.Run("creates a new Verifiable Presentation from JSON with valid empty VC structure", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validEmptyPresentation), WithPresStrictValidation())
		require.NoError(t, err)
		require.NotNil(t, vp)
	})

	t.Run("creates a new Verifiable Presentation from JSON with invalid structure", func(t *testing.T) {
		emptyJSONDoc := "{}"
		vp, err := newTestPresentation([]byte(emptyJSONDoc))
		require.Error(t, err)
		require.Nil(t, vp)
	})

	t.Run("fails to create a new Verifiable Presentation from non-JSON doc", func(t *testing.T) {
		vp, err := newTestPresentation([]byte("non json"))
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

		vp, err := newTestPresentation(vpBytes, WithPresStrictValidation())
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})

	t.Run("strict VP validation fails because of invalid field in VP proof", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validPresentation))
		require.NoError(t, err)

		proof := vp.Proofs[0]
		proof["foo2"] = "bar2"

		vpBytes, err := json.Marshal(vp)
		require.NoError(t, err)

		vp, err = newTestPresentation(vpBytes, WithPresStrictValidation())
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})

	t.Run("strict VP validation fails because of invalid field in VC of VP", func(t *testing.T) {
		vp, err := newTestPresentation([]byte(validPresentation))
		require.NoError(t, err)

		vc := vp.Credentials()[0]
		require.NotNil(t, vc)

		vcMap, ok := vc.(map[string]interface{})
		require.True(t, ok)

		vcMap["foo3"] = "bar3"

		vpBytes, err := json.Marshal(vp)
		require.NoError(t, err)

		vp, err = newTestPresentation(vpBytes, WithPresStrictValidation())
		require.Error(t, err)
		require.EqualError(t, err, "JSON-LD doc has different structure after compaction")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Context(t *testing.T) {
	t.Run("rejects verifiable presentation with empty context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "@context is required")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation with invalid context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = []string{
			"https://www.w3.org/2018/credentials/v2",
			"https://www.w3.org/2018/credentials/examples/v1"}
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
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
		vp, err := newTestPresentation(bytes)
		require.NoError(t, err)
		require.NotNil(t, vp)
	})

	t.Run("rejects verifiable presentation with invalid string context", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Context = "https://www.w3.org/2018/credentials/v2"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match: \"https://www.w3.org/2018/credentials/v1\"")
		require.Nil(t, vp)
	})
}

func TestValidateVP_ID(t *testing.T) {
	t.Run("rejects verifiable presentation with non-url ID", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.ID = "not valid presentation ID URL"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Type(t *testing.T) {
	t.Run("accepts verifiable presentation with single VerifiablePresentation type", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = "VerifiablePresentation"
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		_, err = newTestPresentation(bytes)
		require.NoError(t, err)
	})

	t.Run("accepts verifiable presentation with multiple types where VerifiablePresentation is a first type",
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"VerifiablePresentation", "CredentialManagerPresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			_, err = newTestPresentation(bytes)
			require.NoError(t, err)
		})

	t.Run("rejects verifiable presentation with no type defined", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Type = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
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
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Does not match pattern '^VerifiablePresentation$'")
		require.Nil(t, vp)
	})

	t.Run("rejects verifiable presentation where several types are defined and first one is not VerifiablePresentation", //nolint:lll
		func(t *testing.T) {
			raw := &rawPresentation{}
			require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
			raw.Type = []string{"CredentialManagerPresentation", "VerifiablePresentation"}
			bytes, err := json.Marshal(raw)
			require.NoError(t, err)
			vp, err := newTestPresentation(bytes)
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
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "holder: Does not match format 'uri'")
		require.Nil(t, vp)
	})
}

func TestValidateVP_Proof(t *testing.T) {
	t.Run("rejects verifiable presentation with missed embedded proof", func(t *testing.T) {
		raw := &rawPresentation{}
		require.NoError(t, json.Unmarshal([]byte(validPresentation), &raw))
		raw.Proof = nil
		bytes, err := json.Marshal(raw)
		require.NoError(t, err)
		vp, err := newTestPresentation(bytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded proof is missing")
		require.Nil(t, vp)
	})
}

func TestPresentation_MarshalJSON(t *testing.T) {
	vp, err := newTestPresentation([]byte(validPresentation))
	require.NoError(t, err)
	require.NotEmpty(t, vp)

	// convert verifiable credential to json byte data
	vpData, err := vp.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vpData)

	// convert json byte data back to verifiable presentation
	vp2, err := newTestPresentation(vpData)
	require.NoError(t, err)
	require.NotEmpty(t, vp2)

	// verify that verifiable presentations created by ParsePresentation() and MarshalJSON() matches
	require.Equal(t, vp, vp2)
}

func TestPresentation_SetCredentials(t *testing.T) {
	r := require.New(t)
	vp := Presentation{}

	vc, err := ParseUnverifiedCredential([]byte(validCredential))
	r.NoError(err)

	// Pass Credential struct pointer
	err = vp.SetCredentials(vc)
	r.NoError(err)
	r.Len(vp.credentials, 1)
	r.Equal(vc, vp.credentials[0])

	// Pass VC marshalled into JSON bytes
	err = vp.SetCredentials([]byte(validCredential))
	r.NoError(err)
	r.Len(vp.credentials, 1)
	// VC JSON bytes is converted to vc struct
	r.Equal(vc, vp.credentials[0])

	// Pass VC marshalled into JSON string
	err = vp.SetCredentials(validCredential)
	r.NoError(err)
	r.Len(vp.credentials, 1)
	// VC JSON string is converted to vc struct
	r.Equal(vc, vp.credentials[0])

	// Pass VC marshalled into unsecured JWT
	jwtClaims, err := vc.JWTClaims(true)
	r.NoError(err)

	jwt, err := jwtClaims.MarshalUnsecuredJWT()
	r.NoError(err)

	err = vp.SetCredentials(jwt)
	r.NoError(err)
	r.Len(vp.credentials, 1)
	// VC JWT is NOT converted to vc struct, it's kept as is
	r.Equal(jwt, vp.credentials[0])

	// set multiple credentials
	err = vp.SetCredentials(vc, jwt, validCredential, []byte(validCredential))
	r.NoError(err)
	r.Len(vp.credentials, 4)
	r.Equal(vc, vp.credentials[0])
	r.Equal(jwt, vp.credentials[1])
	r.Equal(vc, vp.credentials[2])
	r.Equal(vc, vp.credentials[3])

	// Error - invalid VC in string form
	err = vp.SetCredentials("invalid VC")
	r.Error(err)
	r.Contains(err.Error(), "check VC")

	// Error - invalid VC in bytes form
	err = vp.SetCredentials([]byte("invalid VC"))
	r.Error(err)
	r.Contains(err.Error(), "check VC")

	// Error - pass unsupported type
	vpOther := &Presentation{}
	err = vp.SetCredentials(vpOther)
	r.Error(err)
	r.EqualError(err, "unsupported credential format")
}

func TestPresentation_decodeCredentials(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	vc, err := parseTestCredential([]byte(validCredential))
	r.NoError(err)

	jwtClaims, err := vc.JWTClaims(false)
	r.NoError(err)

	jws, err := jwtClaims.MarshalJWS(EdDSA, getEd25519TestSigner(privKey), "k1")
	r.NoError(err)

	// single credential - JWS
	opts := defaultPresentationOpts()
	opts.publicKeyFetcher = SingleKey(pubKey, kms.ED25519)
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
	suite := ed25519signature2018.New()

	vpOpt := WithPresEmbeddedSignatureSuites(suite)
	require.NotNil(t, vpOpt)

	opts := &presentationOpts{}
	vpOpt(opts)
	require.Equal(t, []verifier.SignatureSuite{suite}, opts.ldpSuites)
}

func TestWithPresJSONLDDocumentLoader(t *testing.T) {
	documentLoader := ld.NewDefaultDocumentLoader(nil)
	presentationOpt := WithPresJSONLDDocumentLoader(documentLoader)
	require.NotNil(t, presentationOpt)

	opts := &presentationOpts{}
	presentationOpt(opts)
	require.Equal(t, documentLoader, opts.jsonldDocumentLoader)
}

func TestParseUnverifiedPresentation(t *testing.T) {
	// happy path
	vp, err := ParseUnverifiedPresentation([]byte(validPresentation))
	require.NoError(t, err)
	require.NotNil(t, vp)

	// delete the embedded proof and check the VP decoding once again
	var vpJSON map[string]interface{}

	err = json.Unmarshal([]byte(validPresentation), &vpJSON)
	require.NoError(t, err)
	delete(vpJSON, "proof")

	vpWithoutProofBytes, err := json.Marshal(vpJSON)
	require.NoError(t, err)

	vp, err = ParseUnverifiedPresentation(vpWithoutProofBytes)
	require.NoError(t, err)
	require.NotNil(t, vp)

	// VP decoding error
	vp, err = ParseUnverifiedPresentation([]byte("invalid"))
	require.Error(t, err)
	require.Nil(t, vp)
}
