/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func Test_keyResolverAdapter_Resolve(t *testing.T) {
	t.Run("successful public key resolving", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		kra := &keyResolverAdapter{pubKeyFetcher: SingleKey(pubKey, kms.ED25519)}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.NoError(t, err)
		require.Equal(t, []byte(pubKey), resolvedPubKey.Value)
	})

	t.Run("error wrong key format", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, nil
		}}
		resolvedPubKey, err := kra.Resolve("any")
		require.Error(t, err)
		require.EqualError(t, err, "wrong id [any] to resolve")
		require.Nil(t, resolvedPubKey)
	})

	t.Run("error at public key resolving (e.g. not found)", func(t *testing.T) {
		kra := &keyResolverAdapter{pubKeyFetcher: func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, errors.New("no key found")
		}}
		resolvedPubKey, err := kra.Resolve("did1#key1")
		require.Error(t, err)
		require.EqualError(t, err, "no key found")
		require.Nil(t, resolvedPubKey)
	})
}

// This example is generated using https://transmute-industries.github.io/vc-greeting-card
func TestLinkedDataProofSignerAndVerifier(t *testing.T) {
	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:key:z6Mkj7of2aaooXhTJvJ5oCL9ZVcAS472ZBuSjYyXDa4bWT32",
  "issuanceDate": "2020-01-17T15:14:09.724Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }
}
`

	ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	vcWithEd25519Proof := prepareVCWithEd25519LDP(t, vcJSON, ed25519Signer)

	vcWithEd25519ProofBytes, err := vcWithEd25519Proof.MarshalJSON()
	require.NoError(t, err)

	ecdsaSigner, err := newCryptoSigner(kms.ECDSASecp256k1TypeIEEEP1363)
	require.NoError(t, err)
	vcWithSecp256k1Proof := prepareVCWithSecp256k1LDP(t, vcJSON, ecdsaSigner)

	vcWithSecp256k1ProofBytes, err := vcWithSecp256k1Proof.MarshalJSON()
	require.NoError(t, err)
	require.NotEmpty(t, vcWithSecp256k1ProofBytes)

	t.Run("Single signature suite", func(t *testing.T) {
		verifierSuite := ed25519signature2018.New(
			suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()),
			suite.WithCompactProof())
		vcDecoded, err := parseTestCredential(t, vcWithEd25519ProofBytes,
			WithEmbeddedSignatureSuites(verifierSuite),
			WithPublicKeyFetcher(SingleKey(ed25519Signer.PublicKeyBytes(), kms.ED25519)))
		require.NoError(t, err)
		require.Equal(t, vcWithEd25519Proof, vcDecoded)
	})

	t.Run("Several signature suites", func(t *testing.T) {
		verifierSuites := []verifier.SignatureSuite{
			ed25519signature2018.New(
				suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()),
				suite.WithCompactProof()),
			ecdsasecp256k1signature2019.New(
				suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier())),
		}

		vcDecoded, err := parseTestCredential(t, vcWithEd25519ProofBytes,
			WithEmbeddedSignatureSuites(verifierSuites...),
			WithPublicKeyFetcher(SingleKey(ed25519Signer.PublicKeyBytes(), kms.ED25519)))
		require.NoError(t, err)
		require.Equal(t, vcWithEd25519Proof, vcDecoded)

		j, err := jwksupport.JWKFromKey(ecdsaSigner.PublicKey())
		require.NoError(t, err)

		vcDecoded, err = parseTestCredential(t, vcWithSecp256k1ProofBytes,
			WithEmbeddedSignatureSuites(verifierSuites...),
			WithPublicKeyFetcher(func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{
					Type:  "EcdsaSecp256k1VerificationKey2019",
					Value: ecdsaSigner.PublicKeyBytes(),
					JWK:   j,
				}, nil
			}))
		require.NoError(t, err)
		require.Equal(t, vcWithSecp256k1Proof, vcDecoded)
	})

	t.Run("no signature suite defined", func(t *testing.T) {
		vcDecoded, err := parseTestCredential(t, vcWithEd25519ProofBytes,
			WithPublicKeyFetcher(SingleKey(ed25519Signer.PublicKeyBytes(), kms.ED25519)))
		require.NoError(t, err)
		require.NotNil(t, vcDecoded)
	})
}

func prepareVCWithEd25519LDP(t *testing.T, vcJSON string, signer Signer) *Credential {
	vc, err := ParseCredential([]byte(vcJSON),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())
	require.NoError(t, err)

	ed25519SignerSuite := ed25519signature2018.New(
		suite.WithSigner(signer),
		suite.WithCompactProof())

	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519SignerSuite,
		SignatureRepresentation: SignatureJWS,
		Created:                 &created,
		VerificationMethod:      "did:example:123456#key1",
	}, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	return vc
}

func prepareVCWithSecp256k1LDP(t *testing.T, vcJSON string, signer Signer) *Credential {
	vc, err := ParseCredential([]byte(vcJSON),
		WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		WithDisabledProofCheck())
	require.NoError(t, err)

	ed25519SignerSuite := ecdsasecp256k1signature2019.New(
		suite.WithSigner(signer))

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "EcdsaSecp256k1Signature2019",
		Suite:                   ed25519SignerSuite,
		SignatureRepresentation: SignatureJWS,
		VerificationMethod:      "did:example:123456#key1",
	}, ldprocessor.WithDocumentLoader(createTestDocumentLoader(t)))
	require.NoError(t, err)

	require.Len(t, vc.Proofs, 1)

	return vc
}
