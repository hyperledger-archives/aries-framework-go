/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func Test_parseEmbeddedProof(t *testing.T) {
	t.Run("parse linked data proof with \"Ed25519Signature2018\" proof type", func(t *testing.T) {
		s, err := getProofType(map[string]interface{}{
			"type": ed25519Signature2018,
		})
		require.NoError(t, err)
		require.Equal(t, ed25519Signature2018, s)

		s, err = getProofType(map[string]interface{}{
			"type": jsonWebSignature2020,
		})
		require.NoError(t, err)
		require.Equal(t, jsonWebSignature2020, s)

		s, err = getProofType(map[string]interface{}{
			"type": ecdsaSecp256k1Signature2019,
		})
		require.NoError(t, err)
		require.Equal(t, ecdsaSecp256k1Signature2019, s)
	})

	t.Run("parse embedded proof without \"type\" element", func(t *testing.T) {
		_, err := getProofType(map[string]interface{}{})
		require.Error(t, err)
		require.EqualError(t, err, "proof type is missing")
	})

	t.Run("parse embedded proof with unsupported type", func(t *testing.T) {
		_, err := getProofType(map[string]interface{}{
			"type": "SomethingUnsupported",
		})
		require.Error(t, err)
		require.EqualError(t, err, "unsupported proof type: SomethingUnsupported")
	})
}

func Test_checkEmbeddedProof(t *testing.T) {
	r := require.New(t)
	nonJSONBytes := []byte("not JSON")
	defaultOpts := &embeddedProofCheckOpts{}

	t.Run("Happy path - single proof", func(t *testing.T) {
		vc, publicKeyFetcher := createVCWithLinkedDataProof()
		vcBytes := vc.byteJSON(t)

		vSuite := ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))
		proof, err := checkEmbeddedProof(vcBytes, &embeddedProofCheckOpts{
			publicKeyFetcher:     publicKeyFetcher,
			ldpSuites:            []verifier.SignatureSuite{vSuite},
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestJSONLDDocumentLoader()},
		})

		require.NoError(t, err)
		require.NotEmpty(t, proof)
	})

	t.Run("Happy path - two proofs", func(t *testing.T) {
		vc, publicKeyFetcher := createVCWithTwoLinkedDataProofs()
		vcBytes := vc.byteJSON(t)

		vSuite := ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))
		proof, err := checkEmbeddedProof(vcBytes, &embeddedProofCheckOpts{
			publicKeyFetcher:     publicKeyFetcher,
			ldpSuites:            []verifier.SignatureSuite{vSuite},
			jsonldCredentialOpts: jsonldCredentialOpts{jsonldDocumentLoader: createTestJSONLDDocumentLoader()},
		})

		require.NoError(t, err)
		require.NotEmpty(t, proof)
	})

	t.Run("Does not check the embedded proof if credentialOpts.disabledProofCheck", func(t *testing.T) {
		docBytes, err := checkEmbeddedProof(nonJSONBytes, &embeddedProofCheckOpts{disabledProofCheck: true})
		r.NoError(err)
		r.NotNil(docBytes)
	})

	t.Run("error on checking non-JSON embedded proof", func(t *testing.T) {
		docBytes, err := checkEmbeddedProof(nonJSONBytes, defaultOpts)
		r.Error(err)
		r.Contains(err.Error(), "embedded proof is not JSON")
		r.Nil(docBytes)
	})

	t.Run("check embedded proof without \"proof\" element", func(t *testing.T) {
		docWithoutProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1"
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithoutProof), defaultOpts)
		r.NoError(err)
		r.NotNil(docBytes)
	})

	t.Run("error on not map \"proof\" element", func(t *testing.T) {
		docWithNotMapProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": "some string proof"
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotMapProof), defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
		r.Nil(docBytes)
	})

	t.Run("error on not map \"proof\" element", func(t *testing.T) {
		docWithNotMapProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": "some string proof"
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotMapProof), defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
		r.Nil(docBytes)
	})

	t.Run("error on not map \"proof\" element inside proofs array", func(t *testing.T) {
		docWithNotMapProof := `
{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": [
    {
      "created": "2020-04-17T16:54:24+03:00",
      "proofPurpose": "assertionMethod",
      "proofValue": "Lxx69YOV08JglTEmAmdVZgsJdBnCw7oWvfGNaTEKdg-_8qMVAKy1u0oTvWZuhAjTbowjuf1oRtu_1N--PA4TBg",
      "type": "Ed25519Signature2018",
      "verificationMethod": "did:example:123456#key1"
    },
    "some string proof"
  ]

}
`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotMapProof), defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: invalid proof type")
		r.Nil(docBytes)
	})

	t.Run("error on not supported type of embedded proof", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "SomethingUnsupported"
  }
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotSupportedProof), defaultOpts)
		r.Error(err)
		r.EqualError(err, "check embedded proof: unsupported proof type: SomethingUnsupported")
		r.Nil(docBytes)
	})

	t.Run("error on invalid proof of Linked Data embedded proof", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "Ed25519Signature2018",
    "created": "2020-01-21T12:59:31+02:00",
    "creator": "John",
    "proofValue": "invalid value"
  }
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotSupportedProof),
			&embeddedProofCheckOpts{publicKeyFetcher: SingleKey([]byte("pub key bytes"), kms.ED25519)})
		r.Error(err)
		r.Contains(err.Error(), "check embedded proof")
		r.Nil(docBytes)
	})

	t.Run("no public key fetcher defined", func(t *testing.T) {
		docWithNotSupportedProof := `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "proof": {
	"type": "Ed25519Signature2018",
    "created": "2020-01-21T12:59:31+02:00",
    "creator": "John",
    "proofValue": "invalid value"
  }
}`
		docBytes, err := checkEmbeddedProof([]byte(docWithNotSupportedProof), defaultOpts)
		r.Error(err)
		r.EqualError(err, "public key fetcher is not defined")
		r.Nil(docBytes)
	})
}

func Test_getSuites(t *testing.T) {
	createProofOfTypeFunc := func(suiteType string) map[string]interface{} {
		return map[string]interface{}{
			"type": suiteType,
		}
	}

	proofs := []map[string]interface{}{
		createProofOfTypeFunc(ed25519Signature2018),
		createProofOfTypeFunc(jsonWebSignature2020),
		createProofOfTypeFunc(ecdsaSecp256k1Signature2019),
		createProofOfTypeFunc(bbsBlsSignature2020),
	}

	suites, err := getSuites(proofs, &embeddedProofCheckOpts{})
	require.NoError(t, err)
	require.Len(t, suites, 4)
}
