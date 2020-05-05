/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewCredentialFromLinkedDataProof_Ed25519Signature2018(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	sigSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

//nolint:lll
func TestNewCredentialFromLinkedDataProof_JSONLD_Validation(t *testing.T) {
	r := require.New(t)

	pubKeyBytes := base58.Decode("DqS5F3GVe3rCxucgi4JBNagjv4dKoHc8TDLDw9kR58Pz")

	sigSuite := ed25519signature2018.New(
		suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))

	vcOptions := []CredentialOpt{
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, "Ed25519Signature2018")),
		WithStrictValidation(),
	}

	t.Run("valid VC", func(t *testing.T) {
		vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "id": "http://example.gov/credentials/3732",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "degree": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "",
  "issuer": "did:web:vc.transmute.world",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2019-12-11T03:50:55Z",
    "verificationMethod": "did:web:vc.transmute.world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MlJy4Sn47kgse7SKc56OKkJUhu-Z3CPiv2_MdjOQXJk8Bpzxa-JuinjJNN3YkYb6tPE6poIhBTlgnc_c5qQsBA"
  }
}
`

		vcWithLdp, _, err := NewCredential([]byte(vcJSON), vcOptions...)
		r.NoError(err)
		r.NotNil(t, vcWithLdp)
	})

	t.Run("VC with unknown field", func(t *testing.T) {
		// "newProp" is a field not defined in any context.
		vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "id": "http://example.gov/credentials/3732",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "degree": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "",
  "issuer": "did:web:vc.transmute.world",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2019-12-11T03:50:55Z",
    "verificationMethod": "did:web:vc.transmute.world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MlJy4Sn47kgse7SKc56OKkJUhu-Z3CPiv2_MdjOQXJk8Bpzxa-JuinjJNN3YkYb6tPE6poIhBTlgnc_c5qQsBA"
  },
  "newProp": "foo"
}
`

		vcWithLdp, _, err := NewCredential([]byte(vcJSON), vcOptions...)
		r.Error(err)
		r.EqualError(err, "JSON-LD doc has different structure after compaction")
		r.Nil(vcWithLdp)
	})

	t.Run("VC with unknown proof field", func(t *testing.T) {
		// "newProp" is a field not defined in any context.
		vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "id": "http://example.gov/credentials/3732",
  "issuanceDate": "2020-03-16T22:37:26.544Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "degree": "MIT"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },
  "profile": "",
  "issuer": "did:web:vc.transmute.world",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2019-12-11T03:50:55Z",
    "verificationMethod": "did:web:vc.transmute.world#z6MksHh7qHWvybLg5QTPPdG2DgEjjduBDArV9EF9mRiRzMBN",
    "proofPurpose": "assertionMethod",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MlJy4Sn47kgse7SKc56OKkJUhu-Z3CPiv2_MdjOQXJk8Bpzxa-JuinjJNN3YkYb6tPE6poIhBTlgnc_c5qQsBA",
    "newProp": "foo"
  }
}
`

		vcWithLdp, _, err := NewCredential([]byte(vcJSON), vcOptions...)
		r.Error(err)
		r.EqualError(err, "JSON-LD doc has different structure after compaction")
		r.Nil(vcWithLdp)
	})

	t.Run("VC with different mapped field", func(t *testing.T) {
		vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.org/",
    "https://mavennet.github.io/contexts/bill-of-lading-v1.0.jsonld"
  ],
  "id": "http://neo-flow.com/credentials/e94a16cb-35b2-4301-9fb6-7af3d8fe7b81",
  "type": ["VerifiableCredential", "BillOfLadingCredential"],
  "name": "Bill of Lading",
  "description": "Detailed shipment document provided by the carrier to the receiver of products.",
  "issuer": "did:v1:test:nym:z6MkfG5HTrBXzsAP8AbayNpG3ZaoyM4PCqNPrdWQRSpHDV6J",
  "issuanceDate": "2020-04-09T21:13:13Z",
  "credentialSubject": {
    "productIdentifier": "3a185b8f-078a-4646-8343-76a45c2856a5",
    "bolNumber": "BOL000104976",
    "carrier": "did:v1:test:nym:z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
    "recipient": "did:v1:test:nym:z6MknQLHcwKwopce5ji1Ftsurn8mNL58wTxZB238uEMsegUj",
    "transportType": "Pipeline",
    "originAddress": {
      "address": "Quebec, CAN",
      "latitude": "52.9399",
      "longitude": "73.5491"
    },
    "deliveryAddress": {
      "address": "Chicago, USA",
      "latitude": "41.8781",
      "longitude": "87.6298"
    },
    "valuePerItem": "46",
    "totalOrderValue": "126500",
    "freightChargeTerms": "Freight Prepaid",
    "expectedDeliveryDates": "12-APR-2020",
    "comments": ""
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-04-26T20:14:44Z",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..LFKayh8S3hxHc2hZJP-ARH6qZO06pBUJgPg9osvH2OD-OftB-SvIv3Tni_j0fVwK5iYWfChAs8Cvw-czQ2S1Dw",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:v1:test:nym:z6MkfG5HTrBXzsAP8AbayNpG3ZaoyM4PCqNPrdWQRSpHDV6J#z6MkqfvdBsFw4QdGrZrnx7L1EKfY5zh9tT4gumUGsMMEZHY3"
  }
}
`

		vc, _, err := NewCredential([]byte(vcJSON),
			WithDisabledProofCheck(),
			WithStrictValidation(),
		)
		require.NoError(t, err)
		require.NotNil(t, vc)
	})
}

//nolint:lll
func TestWithStrictValidationOfJsonWebSignature2020(t *testing.T) {
	vcJSON := `
{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": "http://example.gov/credentials/3732",
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ],
    "issuer": {
      "id": "did:web:vc.transmute.world"
    },
    "issuanceDate": "2020-03-10T04:24:12.164Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    },
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "2020-03-21T17:51:48Z",
      "verificationMethod": "did:web:vc.transmute.world#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
      "proofPurpose": "assertionMethod",
      "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..OPxskX37SK0FhmYygDk-S4csY_gNhCUgSOAaXFXDTZx86CmI5nU9xkqtLWg-f4cqkigKDdMVdtIqWAvaYx2JBA"
    }
}
`
	sigSuite := jsonwebsignature2020.New(
		suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier()))

	decoded, err := base64.RawURLEncoding.DecodeString("VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ")
	require.NoError(t, err)

	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey[0:32], decoded)
	rv := ed25519.PublicKey(publicKey)

	vcWithLdp, _, err := NewCredential([]byte(vcJSON),
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(func(issuerID, keyID string) (*sigverifier.PublicKey, error) {
			return &sigverifier.PublicKey{
				Type: "JwsVerificationKey2020",
				JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{
						Algorithm: "EdDSA",
						Key:       rv,
					},
					Crv: "Ed25519",
					Kty: "OKP",
				},
			}, nil
		}),
		WithExternalJSONLDContext("https://trustbloc.github.io/context/vc/credentials-v1.jsonld"),
		WithStrictValidation())

	require.NoError(t, err)
	require.NotNil(t, vcWithLdp)
}

func TestExtraContextWithLDP(t *testing.T) {
	r := require.New(t)

	vcJSON := `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
  ],
  "id": "http://example.edu/credentials/3732",
  "type": ["VerifiableCredential", "SupportingActivity"],
  "issuer": "https://example.edu/issuers/14",
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  },
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  }
}`

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	sigSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(privKey)),
		suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(vcJSON))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)),
		WithStrictValidation())
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
	r.NotNil(vcWithLdp)

	// Drop https://trustbloc.github.io/context/vc/examples-v1.jsonld context where
	// SupportingActivity and CredentialStatusList2017 are defined.
	vcMap, err := toMap(vcBytes)
	r.NoError(err)

	vcMap["@context"] = baseContext
	vcBytes, err = json.Marshal(vcMap)
	r.NoError(err)

	vcWithLdp, _, err = NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)),
		WithStrictValidation())
	r.Error(err)
	r.EqualError(err, "decode new credential: check embedded proof: check linked data proof: ed25519: invalid signature")
	r.Nil(vcWithLdp)

	// Use extra context.
	vcWithLdp, _, err = NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)),
		WithExternalJSONLDContext("https://trustbloc.github.io/context/vc/examples-v1.jsonld"),
		WithStrictValidation())
	r.NoError(err)
	r.NotNil(vcWithLdp)

	// Use extra context.
	vcWithLdp, _, err = NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)),
		WithExternalJSONLDContext("https://trustbloc.github.io/context/vc/examples-v1.jsonld"),
		WithStrictValidation())
	r.NoError(err)
	r.NotNil(vcWithLdp)

	// Use extra in-memory context.
	reader, err := ld.DocumentFromReader(strings.NewReader(`
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
`))
	r.NoError(err)

	loader := CachingJSONLDLoader()
	loader.AddDocument("http://localhost:8652/dummy.jsonld", reader)

	vcWithLdp, _, err = NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, kms.ED25519)),
		WithExternalJSONLDContext("http://localhost:8652/dummy.jsonld"),
		WithJSONLDDocumentLoader(loader),
		WithStrictValidation())
	r.NoError(err)
	r.NotNil(vcWithLdp)
}

func TestNewCredentialFromLinkedDataProof_JsonWebSignature2020_Ed25519(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	sigSuite := jsonwebsignature2020.New(
		suite.WithSigner(getEd25519TestSigner(privKey)), // TODO replace getEd25519TestSigner with LocalCrypto/KMS
		suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		SignatureRepresentation: SignatureJWS,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKey, "Ed25519Signature2018")))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func TestNewCredentialFromLinkedDataProof_JsonWebSignature2020_ecdsaP256(t *testing.T) {
	r := require.New(t)

	// TODO replace ecdsa.GenerateKey with KMS.Create(kms.ECDSAP256TypeIEEEP1363) and use localkms and Crypto for signing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sigSuite := jsonwebsignature2020.New(
		suite.WithSigner(getEcdsaP256TestSigner(privateKey)),
		suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		SignatureRepresentation: SignatureJWS,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	pubKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(func(issuerID, keyID string) (*sigverifier.PublicKey, error) {
			return &sigverifier.PublicKey{
				Type:  "JwsVerificationKey2020",
				Value: pubKeyBytes,
				JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{
						Algorithm: "ES256",
						Key:       &privateKey.PublicKey,
					},
					Crv: "P-256",
					Kty: "EC",
				},
			}, nil
		}))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func TestNewCredentialFromLinkedDataProof_EcdsaSecp256k1Signature2019(t *testing.T) {
	r := require.New(t)

	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	sigSuite := ecdsasecp256k1signature2019.New(
		suite.WithSigner(getEcdsaSecp256k1RS256TestSigner(privateKey)),
		// TODO use suite.NewCryptoVerifier(createLocalCrypto()) verifier as soon as
		//  tinkcrypto will support secp256k1 (https://github.com/hyperledger/aries-framework-go/issues/1285)
		suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier()))

	ldpContext := &LinkedDataProofContext{
		SignatureType:           "EcdsaSecp256k1Signature2019",
		SignatureRepresentation: SignatureJWS,
		Suite:                   sigSuite,
		VerificationMethod:      "did:example:123456#key1",
	}

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext)
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)

	// JWK encoded public key
	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(func(issuerID, keyID string) (*sigverifier.PublicKey, error) {
			return &sigverifier.PublicKey{
				Type: "EcdsaSecp256k1VerificationKey2019",
				JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{
						Algorithm: "ES256K",
						Key:       &privateKey.PublicKey,
					},
					Crv: "secp256k1",
					Kty: "EC",
				},
			}, nil
		}))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)

	// Bytes encoded public key (can come in e.g. publicKeyHex field)
	pubKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	vcWithLdp, _, err = NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(func(issuerID, keyID string) (*sigverifier.PublicKey, error) {
			return &sigverifier.PublicKey{
				Type:  "EcdsaSecp256k1VerificationKey2019",
				Value: pubKeyBytes,
			}, nil
		}))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

//nolint:lll
func TestNewCredential_JSONLiteralsNotSupported(t *testing.T) {
	vcJSON := `
{
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3c-ccg.github.io/vc-examples/cmtr/examples/v0.2/cmtr-v0.2.jsonld"
    ],
    "id": "http://example.com/credentials/123",
    "type": [
      "VerifiableCredential",
      "CertifiedMillTestReport"
    ],
    "issuer": "did:elem:ropsten:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
    "issuanceDate": "2020-03-09T18:19:10.033Z",
    "name": "Certified Mill Test Report",
    "description": "A mill test report (MTR) and often also called a certified mill test report, certified material test report, mill test certificate (MTC), inspection certificate, certificate of test, or a host of other names, is a quality assurance document used in the metals industry that certifies a material's chemical and physical properties and states a product made of metal (steel, aluminum, brass or other alloys) complies with an international standards organization (such as ANSI, ASME, etc.) specific standards.",
    "credentialSubject": {
      "id": "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
      "cmtr": {
        "companyName": "Steel Inc.",
        "companyWebsite": "https://example.com",
        "companyAddress": "3260 46 Ave SE #30, Calgary, AB T2B 3K7, Canada",
        "companyPhoneNumber": "555 555 5555",
        "companyBrandMark": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6eAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAACnWSURBVHhe7V0HmBRF2pa8bCAsu7CywJJzEliiiICwgCQDUQUUMRAlbI7AktlDwikIBhA9RUFO8czxP7lDQKICCiKCAcN5eoY70/e/X2912zPT09MzO8vOLt/7PO/T01VfVXdXfe90VXd11SUCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAL/sWHDhkoZGRmXZmVltcnOzu7jztzc3NZgHFhRJREIyh7YweHw3SCEW7FdmZOTswv8EL9/w5Yc8FfwJLgLeawAb4Gwum7btq2COoRAUKpQDk7cAQ49GyJ4BvxWOXpQqfJ9GpyF47Xj4xYeXiAIQWRmZjaBs86H457WndhMhH8GvgCuwf4MbEeAibjD1EtPT4/Ftgbnk5qaWp33kV8jvlPA+YfDLgV8AOl2g//S83TjhyCyyW2onZBAUNKYMWNGFTjlzeCbcODflaPqPIewTXDw8cF2WuTZDPnfjvwfB780H5fPA/Gv45gTuJ+jkggEFw6zZ8+uCkecCYf82OycvI/wxXDOjsr0QqAcjtcJx70bPG8+H+yfAaeykJWtQFB8gCOG4d85GU73qckRf8X+U+AAxJdXpiUCHL8iyE2y7Xxe+jli/yy2sxBXWZkKBMEF+gSD4GT8NEl3uv+C69Bn8Nl8gmPGcH8C9sMgMH6axXefXBO5Qz8VcWNxnIHog7QsqjNzMwx5Pgj+wufLxO/jYF9lIhAUHXDUunC2bbqTgXzHWI/wesrEBXDwBNhPANfC9u+wDegpFjs2+AF+78J2JfIbzUJTh3EMFjDS34d8fjblvQUirKNMBILAAKe8Ec70ne5Y4MsI40eqBvh9BBz3StjdjXjjDmPDL8Bz4FEzkf48aCsmxPODgINgAX4njRo1yvG7EJx3B6TZY8rrG2xHqWiBwDng8NzX2GBypq+xnaiiNfCdBeF5CGdnd3dk/rfmuweL5k7Y9kMTK14ltQVsw/mRMbZXIO3t4J+Rz1vgj5y3mQg7Cy7gR8IquS2QZ3nYTwVZHFoeuM61CJe+icAZ4CyN4UD7TU74rLk5ovoiOxFutO0V30PYcqQfBEYq86CBn0Qh/75gPnjAfGzs81v5FyHC7srcFjg/FvdrpjzeRpi8PxHYA07TG9T/XfkukArH0Z5MIbwP9vlFneGY4KcI/xNsOmkZXEBwRx7H5w6++6PmJ3E+LZWZV3DzDLYLcf76kJev8LuHihYIXAGnGgon0Zsx7Cza0x40QS7D7+dUuEbs7wWv86cPUFzAeVfEOY7H+Rh3FfzmDv7diAtXZl7BT81gy/0iTvs90gxUUQJBIeAYE9mplHMdg5M0nTt3bgQcbzX2zYMKX8Z+f5UsICDvysi3FfK5BuRHu8nINxe/1+D3QvV7Jn6PhW13MFoltQXsyiPtOPAjUBfKMbCzMvEKvl7Y8VAVTvMzjj1aRQkudsAh7gC1YSLYHoGz1Oa2PPbfNznaKXCYSuIXkBcPab8R+dyPPPg9hHvfxSeR5lPk8TS2GTi/nnYjeREfBrsFSKc/1uVtOqJsBzMiXV3YHeY0SP8b9ieoKMHFCjjCdewMyimO8JMmOOIy7OtvoX9EeBY7nUriCGlpabWQlgckGp19Ky7NzKBVqfMod/Ysmjp1Kk2bNo3mzJlD81NSaEFWpmUaRW4CbgGTvIkF58zDT47pafD7QV9js5AmGrb/VPbcTLtaRQkuNqDtfQUc4CflDHznaIntKyaHOsBhytwRYN8RaXkA4f/0fJh5Odm0LnMuPZl8M7088zraOyWJjt3Qk45f35mODe9IWa3qEpIbXNmwDh1u05D2dGlPL13enXZcPYQ2TpxIi9PTjTx14lifgFk8ApjPwQycTzXY7NBtIf7nEWb7hE2leUel+d7pkzFBGQIchb/i055WYXsE5K/4+K017/8O3u3PAD84UVek5TfexoheFsUDuTPp9axxdDwliU7edSWdnHoFfTClF70/sTudGNfVp0AONWtABxvG04H4ODoYfykdalCXdnfrRE9eP4IK5s4xRKLIDxhWcZOOz8mEcjivpbodfu/xJZJ58+bFwe6Usv+Sn5ipKEFZB/9DotJ1MXwGsdyC7b/V/n8QP1SZ+gT/ayPNQ6AhjGV5GfTsolvp+OKR9OGCQXQqayCdSukfNIEcblqfjrRKoKPtG9FbA3rS1lsnoDmW5SIUnA83C11e/iEsTbfB7xd8NbdQLjyWS3+6dXzFihURKkpQloFK36qc5L9wAn5ipDezuCN8mTLzCaSZjDT8hl1zumXzM+j5lbfRh2uupY9WDqfTS662FcihUV1oeWIC9a9TjcLKl3MRSDj2k6LCaVmdaHo7oa5XgbzXpSkd69GMDg3oRNtuHU/5rv2W9yCSy/lcdeB8s/R4/H4IQbYdd9h0A7XmIrYPqmBBWQUqerLuIOATqHSjD5KamtpAmdmCmyewf0zPJy83m7avmkmnN42lj9dfR2fWjrQVyPsQyOormlJ8eGUXUXhjg4oVaG10DVuBHL+iJZ24qjUdHZ5ID0+/Rb8+vi5uLm40//vjT4AHUerxaSrYK2AzT7dHWnmyVVaBym2FSv5eOQZ/WKT/5g66o3cNyIP7Lsc5HXPd0jQ6suUWOrt1LJ19YLRPgRy7ozeNa1nbUgi+OCkinN7xIZAPBrelk8Pb054JA2h16h99FJzzIVxjY+SjDa5E2Ksq7mfEJXK4DcrB7m/K/jvk01yFC8oQuKP6hqpks+O8zx1SZWML9dRL66swH183h84+NYHObbvBkUCOz+xDverXsHR+pxwSHkaHHAjk1PWX0cnxXemJuyaZr/VrOLf2llz1nT5Rce/zXZHDvUHZ6x+JvayCBWUFqNQbVOWaHeYjOH2CMrEFbIeBWnNsfl42vbl1On367ET6ZOdNjgVyZ5f6lk7vL++Kru5IIB+O60ynJyTS7mnDaUmW8XiY3+/MQj7cVOQhJvoL0ns4zA64e45UeRDSXq+CBaUdycnJUahU9yHp3+Nfsb0ysQWch2cf0d5+58/Ppv1PTafPXrrFL4E8Pr6TpbMzG6Evkt2qLnWoVpW6V69K6QmxVLtSRUtbndsbXepYIGdu7U7vTh9AqzKTjevH9cxEPnxt/CEVh/3qpDxgr41Jw/asPNUqI0CFrlBOYBD/hjeqaFvAEXrBXhvAuDg/m448N50+f2OKXwI5mTmQEutV93DyapUqUI/YSFrYvj69N6g9vduvDY2MjaIZ8bUos14MdQ+vQhHlXJ9u6ewbGeaXQD6+syednNWP1mfepQvkd9w9py1evJjf+H/FYeCryNsWaWlpzZFWfwm6SAULSiv4pRkq0uVDI1TwGhVtC+7Uw1Z7jLsAd47DL86i87tv91sgT07qaunkm/s2196DPHFFM+oHYYytW4MqlruEqlcoT7fUrk49IZAltWtapmU+1yLeL4GcnXk5nZnXj+7LMkTyG65xErZT9bLB/nDkbQvYLVL2P+KuI5/tlmagEgtUZepOwU9zfH49xyN5Yc+fwqK9nUN7nptDX+ybGpBAZvZubOng2wa00gSypnOCtt8nOoI2tI6nhY3rUKMqlbSwzBjvnfrUS6P9Fsi5eX3oTPoAujfbeML1M8qjH8pFm+wO273I2xbcZIWd9seBbb4KFpQ2oOKjUYHmb7x5soVuKtoWsNuop3txRwp9eXhGwAJJtHhytX1Ia+1N+v4RHWlWizrUNKIKHe7bmo72bklHuzWnV9okUBiaV2viatHjcTEe6Zm9oqoGJJBP0/vSmZxBtDqnsE+Ca9XGcunXi999kL8tYJOvbL9FOWszQgpKGVB5PORbFwc3H1arKFugwkfrae5fn0lfHptVJIHEV6vi4ti1wyrSkRu7agLJ7Fj4ZGtyQi2tD6IL5MhlTegyNLE47qHa0ZRQvrxLHsw2VSsFLJDPcvrTiQXDaVFO4Zt3lBV/864PK3ka+dtC/fno75EyVLCgtAAVWBkVZ56S81OE+fxOnOfFRbrPOc3SJdl09t25RRLIidyBHo7NXNqrsSaQFwa1paH1alKPmuEuAtnboRHVQl9kWs1qNKtGlGUeUeXLFUkgny8cQHvzx1GuKiNc9w9qyx14n5NAwHaVsj+PspUlGkoTUGnXcOXpxP5tKsoWsONZSLQ0/3g9jb46NadIAjk5P8nDseMjK9M747sYgxU3dW+khU+qF02vdW1Cz3doSJdXC9fC3mxcl/6v/qUUD7GY82DGIqyoAjm/dBDtzL/DKCeduNtm4hi2YBGxmNgeW/lupDQBlcZTb2qVjco77WQSZzhFO9hq7zs2bsiirz5OLrJAuInVNKbQ2XWGVShHb8KBdYGsTWxIsZUrUvuoMC0ef8XULTKMakMAOxMupWfjrYemdKhaOSgC+XTlMCqYn+YiEJTDERzDJ2D7prJ/TAUJQh1LliypiQozf7DkMp+VNyDNI2yfl5tDHxxJDZpAutT3fAfCfHJga2O4++GB7egomlgt0a8YFh2p9UH2t06gTfGxlmmZg6uHB0UgXxQMoYMF442mlk7+w8BxbAE7nreLBfIjN09VsCCUoVeaqrizTlZiQhu6Key1z2wf2ZJJX3+SEhSBnIJA6rp10nU+lfSHQPQXheZOOn8Pcr+NQFIurRk0gXy1dihtXVz4fkQnBJKN49hC/Rn9V6W5WQULQhmosKdMFb1QBdsCzmDMonjicFrQBLIvtZ+lczNjwirRVXWrU0GnBh4CyWsQS/3QzKpu8fRK51jcaYIpkA/WjqG8P8qN/1xew3F8Ara8yhXbP66CBKEKvlugovRPaXlmDp+zBfJLQdhqjywf2JiliSNYAtl4g/cxWDobR1ShhW3r0dW1o2hEbBQtaPTHi0I7BqsPogvk6/XD6bFlM80C+Qnl53NeLdhOU2m+gH2JLv8g8AFUaqJeweCLKtgWuHvwlDxamn/+X3pQBZI6sLmlcweD3Jk/0KlxUAXywfrxetlpRHkOwLFsAVG01u1Rlh1UsCAUgQriSdj0Cr5dBdsCdtrHQIvyc+j8x4XiCJZA+jb33ocIBne0ig+qQP71wEhav8hl1K+Tl4D8QZX27gjUhtILQhSoIK09zHS4sA1P4KA92t32l8LOebAE8iEEUrd64aPb4mJeQmzQBbJ73a1mgTh6fAu7x1WaJ1WQIBSBCtLW50CFHVNBtoDdMFWx9PbfCzvnwRLI/swBlk4dTF5fKyroAvli82jtO3tVLkdxHJ9AOerfrR9XQYJQA+4GYaggfUbEVSrYFmzH9vwO4JMPU4MqkE0Tulg6dTDZLrxy0AXyzcPX0aal83SB8Ghfn6Of0bQdbrKXYSehCFRSG1VJ3Fkcr4JtAVttBsF1a7JdxBEMgaQMamHp1DqbVwujlwe1oeRWl1LvmEjqEBVGzatWog4RVah3tXBKrVOTUmpZv2Q080C3pkEXyCvr7tQFQpmZmU1wHFugvFvo9hCITOoQisBt3hh/hQrz+TSFly5AGu2Nu3v/IxgCubKFfQf9rnbxPl8U/qNJPQr38lWhzsfa1gu6QN5/cIIhEJSRz+Hvt912WyXYapNlc7NVBQtCCaicVFWpv3JzSwV7Bf8zKnt6+bmMoArkNAQS5+UNus6Xh7bzKRCeWXFwRFXL9DpzGsUGXSBfPTrGGHqCPxunnyefYHts71JBglACKmalqqATKsgWsBusC2TfbtcOelEFsj/Pepi7zstiIozBir4Eck/tWpZ56BweGxV0gXz72ChavciYCSUVx/EJlOdbqvwXqyBBKAEV86CqIEdDJGBnfIv94THXDnpRBbLx5kRLZ9aZlZjgWCD7EupSLbepSc1shY56cQhk88q5ukCW4Dg+gfJ8QZX/fSpIEEpAxTyhKnSnCrIF7NKVPZ07FVyBpAxuaenMzErlLqF/jOnkWCA8efW4CNch8+58p1fzoAtk26pZWtmgXNfgGD4B2yeVvYzJCkWgcnapCtqsgmwBW312Djp/xlUcRRXIla28Ty96RXx1j9ndfQlkS0y0ZV46H+lQP+gC2bV2hi6Q+3EMn2A7Zb9dBQlCCagY7RaPTqWjb89hu5rtmV+dC55APoJA4qp776Cv7NPUb4G8Ex9HDSpUsMyPmdWkdtAF8uI903SBOH2bvk6V5y4VJAgloIK0Wf/8EIj2gdTa1X+M4A2GQPYvHmTpxMywCuXp4KRulgJ5qUdTeqZTQ3q1YyMPgfDyB3dGRljmybwaHfVgC+TpNcbI3m04hk+g/LVZGrF9SgUJQgmoGG08ELa87oVPwG5zoUA8XxIWRSCbbutm6cTMIU1iLBfQYYF0qVHYzxiovih0F8hfa1tP/8NsVrVS0AXy2J+MCeYcrQsCu0fZHn9QW1SQIJSACnqAKwjcoYJsAftNbF+wIrgCmTe0laUTM+8dBCcOUCC8Pkhbmzl79/dpEVSBPFxgTC7n9I6sDxR1ZC+4wEDFaHPwwvFfUkG2gN0ats9fGLhAHpt/FXVHh7xby1jq1jyGujWLoegI7wvjdKoTRYlx1SiRt7GRlBgTSV2iI6hLzXCKqlj49WDNihWoc0QYdQ6vQp3DKlPnKpWpU+VK1BmMs/nCsF1UFUpEPl2jwZgI6or8tw5oHrBAHlhujMdyNAcvyvM1Vf4y22IoArd27VsQVJDP6TMZXJHKAQJ+zPvnOZdbOmuocHXvxgELZI16UYhy0maC9wXYaWuscz2oIEEoAZWjrQGCivpSBdkCtrPYnnlob2Bv0suqQL75y2iar4a8ozyTkJctcnNzy8PuJ2V/jQoWhBJQMZ11h0eFxahgr4DdTbr9ay/+8amtPwLZuSSJhvZoQEO71aehifWpfYL1bOzR6EQPbhZLg5uAjWNocMNaNKhBNA2qV5MG1a1BSXHVqWalwse4dSpXpIE1ImlgtQgaGBlOAyKq0oCqYRoHhlelrmHWj5D5BeRg5DO4bnUaUq8GDWlQk54Y1DIggZzZcqNWLqostaXb7MCTyOn2uIP4nC5IUAJQky/8xpWECrtCBXsFbPrplfqXrcEZzZs8orWl897apb7tMtBOO+m8iOeexvFeR/juu6pVUDrp+zZM1soF5fkjj3pG3raAnTaujcvfyUBRQQkBFfShqiifU42aR/MuW5rt8bIwEIFc2aaOpeM+DUf1JZCpjWIpKSaKkhvE2gqEF/EcEmU9wvehLglBEcjOVcZbdKdT/2Qq+49UkCAUgUrSJmBARa1RQV4xY8aMKrDT7jjM44eK9sntx/ePpjoW36A3jg6nk8me66S7C8TuTbq7QNbXs/7WJK1lnaAIZE2+MZI3F/n6BAtJlfszKkgQikAF6U+mDqogW8D+Y2VPz/7V9ZsQfwXyzqphlk4754rGLuukB0MgB1o20GZ/dz/WlbWjiiyQTx4cq4uD+x89ka8tYBOOctQ66Oh/OBoaLyghoKL6ckVh+zsqrrYK9grYagMcmStXuDaz/BXIxuk9PRyW+frUXkEXCK9ye0O057II8WEViyyQV9bcrpUHyvBLJ5N+o6k6UC9DJ4ISlCC4g4iK0mZJxL+Zz6WK4QTGuxDmO//8o5nlr0Dmjmzj4bAd46sZy0AHWyCPNonzOB7z7aTWRRLIn/NTdIGsQ34+ATt9DNYPTgQlKGGgsrR+CARyrwryCtgYq0kxNz8Y+NSjfdp6OmzGwObFJpAj7RtRQmXPoSf3dW0YsEBOrh9nlAUc3udydQUFBVVh92+VxucquYIQACpsjqqwc74eUfLkcspWI3+H/d7BwruIPwL5+OExFGsxxD2qSkV6dkqPYhHI7tYNqJnFHL7JreoELBB9bl6U4bvIqxxoC/zBjNfLDmkcvXEXlDDQzGqIytJXPvL5Fhg22mQDOh+8v/Au4o9A9q8b4eGoOrMH4C5SDAKZV8f6pWSfOlEBCeTMuuspL8eYMG4K8vIJ2L2i7H9NTk6uq4IFoQ44vf7YcasK8gpuiqlKNnhkX5pfAvloyxg6tHo49TRN9VOlYnmKDq9EL91RPJ301Q08H/XObBpLBwe3CUgg25dO164dZXbWSV8Cdj308uLyVsGC0gBU2kRVcT/gjlJNBVuCO/N6RetcVZBN50/71wfhF4W6QOpHV6WjeUl0PAf9j2LqgxxFH+TepnG0uPEfn/eyQAJ5inVi1Wjz3cPRBNQoW/M6LI4mCheECHC758XutadZvirPvD4ItkZz65nt6X4LpH1C4Zro47rW12Z35yXYilMg+vogHSML+z9j6tUISCAbFhTOYMLXjz8Un1ONwqYjbLVmLPgd9qNVlKC0ABWoTwPkcxFP2Oizk/8dPMi/ea3CI/9M9ksgdWsWvkm/e9xlF1QgU+ILJ3W4qk41vwXyxpJJmjiY/E5DKxAfQHm9pKcB5QOp0gg0nXi+WG0ya/y2nR0Q8SPZjv8V8fta/NbW3Vu2JJvOHJjtSCCnN43SnJS5L2/gBRXIA23racftHRvpl0COL76W8nOzdEd/gsvCF3C3MDdJeRZLn8tMCEIUcPitXJHYHrN75MvjsmD3har0VbCfrn7ThrWZdP6gb4Ecu+cazUlb1Y3S5ua9kAI52Ks5VSl3ifZlolOBfLIwidbmFi6Wg+s9l56eHltYGt6xYsUKbo6e1csGv2UOrNIM/Lu1RCXqbeUbVLAlEJ+rKv3fSFctN7dwEgLmIxvT6Pxee4HsV2OxJvdpfMEFwjMrdqsRTq2jqjgSyKc5V9EjuYXT+oC/4pr7FpaCPWD7Z71MOB3utrLkWmkHKnIHVyj/88HxI1WwB9LS0mrB7kdlmwPbsJyc7D28z3x8Uwp9biOQ1/KTNIFsvLVriQgkuUksxVWu4EggO7On6E7O9LncMwPloTVDdaKMHlBRgtIMVGxjVKjm+OAKFWwJxGv/kKj8b5EueuXK3Ji83OzjKi1t35RMn71uLZCH7uqtCeTdFVeXiEC2dWmoHf/EMHuBPJ8x0d3Jfb4xR+e9Pmy/1tOB36N85MVgWQGaAvoHPT+jrd1WBXuAKx123ykn2MBhS3NT6s3PK/wQi7l5bQqdfWGyh0BWT+lGnRtHa1OPloRA3u3XiiIqlKfDQ9p6FciutD+eWKEsnuFls7ULtwHKhIezG3dSRUffiQhKCVDJlVHJ+p3g73aOATHpk1r/mpGR0Z3D1i2fF7dwQfYBFU73rEyjUztvcRHIkomdadaQFiUmEJ44rn9sJO0d5Dma98ydvejJVJfFOV/g9z/aBdtALTJkfiHIaU84SSsoZUDF9gf1MVpe526CmHjIvLEYqO4M29blRi5dkKXN/8tcujCT3t5yuyGQrDEd6PHZl5eoQLJbxtHrV7VwEciJ2/rQfWmFn9Cqa3rM6bB02Gpzh5nS/gL6HOUrKKVAJWuLdqKSf7N7KYb4waAupo0q+JJt20ZVWL4oc6PuMMwdq2fSRw+PpzkjWtH7a0aWqEBe7N2UdvVpaghkz22DaVlmmnGu4Cr8AZRXl2MLXLfLtzJMDlPRgrII1dTS2tPYfo79OBXlAcQvNzmGyyQQyxdl3ZiXYwxloZULMyj/jmHG8gclJZATg9rSU72b0LEx3emRuyYby6iB36HpOFadvi+Ug732R2ImymC/fBB1EQCi4OHw/1KVvsdbexp2FRGvLSsG/ux+x1m9PLNJfl7WG7oDMe9bNJf2/+mGkhPIkA60Y8IIWpJpTLrA13ggPT29pTptW3DfDPYud0jFL3D9jZSZoKwDTjAC1GY0wfZZFoOKcgE/3oTNOeUk32P/ShVlYHFe5s24m+hv4TXy4L/d+eMvmEDe7duWdk0YScvTU41zAL/Dtc3xdm3u4PdAsDePsdKIMF773Oc8Y4IyBlT8TJMT8BT/lu8D4BytEX9e2fLz/34qysCyZclR83Mz83JzsvVHxBoLclLpqezJdCh1aLEI5K0BPemRyTfSoowM45ggvxnfivOsp07PJ9D8aod02oMJCzr6eEpQBgFHMndEVyHIUiQ8pAK22osybH8GLSemW7o0tfqCnKz03OzsT035alyTOY+2JU+mN6aPpPdu7h2QQPa1ak7P9+9DD980jlYmG7Ova8Q58ROmB3GuLdTpOEE5vhbwPyoPvrYfTHkuVXaCixTsINqsHMohNntrkiC8E+L1Ownb3uOt/8Jt+dysrJHoJO+E3S96GjNXZqTS+rnT6C9TJ9COyWPo6Zuuob+NGkTPjehPu0YMpJ3XDKNto66lzePH0ro776BlqS7NJ4PI/wREkenPHYOB5mIC0pqbVB9j/z19H3najjoQXCRQHVNtMR0mfj/jzfG5owobbZp/ZXssIyOji4q2BBy3GpxtLGy3gGf0tIESefCd4h9gPs7H73mocD5hSDsPNDcH/4Zz5G9h9P21MPU5BEVw8YDvJItNDrIbjmQ51ojFA1vtYyxFHtV6b3p6eh1lYgv1z30N0mGTzeskvo7tB+B5kJtx3Ifg3x/h91HwZfzmBTJnIO1VLDiVlV9AuvLI4ybkZYgUvz8H78JvszgKYC7iEHgCzjIT1J9u8aNNry8TYTMKNp/pjoXf30Io8518V3EhwXcMnN9knB+LTT/X30C+a/I1aE/gsP0F13unSiYQWEM5jdb8UI60wNvHVnC+Goi/G/yZ7RV/xP56xHVSZiUCOHt9CDYX52L0mxR3IrwDthyn/xnwNzCOPrcVCPipVTM4jTE4Eb/fYqdS0R6AMzaBzWbQLBROx5NA5HI/xck6G0UFnJxHI8/g8wX1D8WY/OnxXxHWDXe49vhtNKkQdgjpWqssBAJngNOEQRTmObN+xn4Bz5iiTDyANA3gcEth6/GYF+HfgDwyNpmbbhDNpSpZQMCxyrMwkd9NOK8N2BpPoHTieF8ibhnsGsE+EvsrEa6JGL/57lHA16myFAj8BxxpGGh8D4LfZ+F0k+yGzGuPeXNzh8D2fqRxecvuxq/AfeAu2N4H5iHvTGynmol4HoKfi7i12H8Gv9/DVptYwp0I/zf4MGyH87f2fC4I53nCjKUe+DdE4/HCUyAICHD2cDjcIjje/3Qnw+8PsJ3sawCfeoyciPTJ4NP4/YmeRzCI/PjFHj8JyweT9PPhLcKngOY35Nw/WsB3E+3kBIJgAg7OUwk9Aycz2vf4fRqcCafzuXCoDn7ShTS8lsnNSngPgZwvD448iu0xkB/1Mk9xGMj9hhexvwlMQbrR4GXuAsV5xCF8LmyMOwZ+/w4+irgGykwgKD7A0TrC8bbB6Ywl3EBu2/Ob8+sQ73N2wmCCm1JoMvHTNxaZ+c09v1N5HOdTok/UBBcp4Hg8rRC/NDS+DWEi7Btsd2A7nW2UeVChjs3zd7Eo9TU69OP/AK7jzrkyFwhKDnDWSDRrJsApXwHNdxXdYbnfsRNcBttJ2O+BraP5bNkO7I603NFeArLwjMnbTOS7xUs4j1tgX0MlFwhCC3DOenDU6eB20DxVjiVh8y34OX5zP0Mj74MudwUrwoYfHfNTrRk4rtevIwWCkASctjzYCQ7MnWbuiO9x4vhW5HS4O7yNLU+nOgO/O1yIl48CwQUH/9uDPeHk12PL32Pwx1s89SlzNvanIm404kbiN7/91sZ3YZ9H4epPtzSin1Ffy1QQ+kAFRnJlBkqk9znjxuzZs6u6p7tYJhNQAnK5s/A6iyq6yODPbs3liryrqyhBIFCzffPbXl7yzOVJTiDkSlFZewUfzz0dwvqo6DINXGuxCoTvSG7571JRAn+BwuwF8jcL5gItEkUg9sC1ikBKA1gcKLwi3zHcKQKxB65VBBLqUM2q024FGRSKQOyBaxWBhDpQaHe6FSI7KI9N4k9D7wHXBUru5KvDeAXsRCAmikBCDFlZWa+6FaLPNQCDCRGI67WLQEIMKDSXjjkKda+KCiqQbxL4mgXfNx9fncMBNxt3Ws5IjvAeIH9ExMPQrdK5EHY8QHGmk6Yg7oaVwethz6NvX9Dz8Ebk/Sq2G9X7D8vBjrAJCYFkZmYOhC1/oWh5Le5EPty62IprS/b3fNX3LGPAR9zzdcgkldWFAQ7oMnsg9otlIUfkzWOPzJUVMFExQ1S2GtTMJMYahAHwe6SfqrLzABycZ2N81yKdIyItz3KSqLIzgLgSFwiurTnsXD4tDoB/RT6NVZZegXrjb+c9/hD95ESV3YUBCsf90e47Kiqo4AtzO07AdBNIOew/b2XnL1EW81SeBvjNtoWj+U3k8W1GRkZHla0GhJe4QFB2t7rZBEQci+cOHqCy9QCO0wLxPseyOeAFF4jHBMdwittVdNDAF+Z+nEBpFgj+uSZY2QRClMX/kF9TlbUGhD/hbhcokf9+ZGnMUYWwEhcIbDz6gIESef2A8muvsnYB4l90tw+QF1YgOCB/xml1Ijzj4HZwmxOicHia/blw3mYqaxcgfgTijRGuJlpNiMCPna1sNULAxuzksNWXNDCT2/+WT9ZM5PO1ut0vUllfMm/evDjs8wwiRjzS8bcZj5ry8UYehOjSfGXiLtJVZR+yAkEYf35sWfZMxB8HvTXL3ka2LhPVpaWlNbew4+PwpHeWx/BGpBmhsr0wgOLDceCitgtdiIt4Dk7cRB3CFrAN+CkWf3kHe/eKWq2ifYLT41gH3dK/qqL53K5zi+Nz66+ifQKd/7awd5nLF+UyQ0WHrEDgEz6nDYINz6rC00l6zFVs/gNjWB0DYTNVdOgDJ5sIfut+EUUkLy1wuTqEV3gpPEcCSUlJqWeR1ms72Aqwv9stj8MqiuOMJRWY2P8Pgv2axhNpXF7CYt9Y9gz7pVYgOtBi0FYcNhN5LlfRGnjf3YYHUqro0gG+9eNC+NbqciFFIfLjbx4sm1w6rCoIYY4Ews4UaFoGHIHnt33bLY83VDRXfrI5DnmfV1GOwOeHNO53uLkqukwIRD1B/MmcHvvPqWgN2Oe5iN2PEa6iSw9w0jzv60RcEH/Vdg5by6n+/eSTKntL4BjFIhDc5rlvxQ5oSdgtAF2WXGMizFhDw5tAUE41sG+Zr07OB/SY/R1ptaWoGWznHl/aBMJAGn1Jbo0ot90qSgOOUTYEUhTggqNREPxpqss/JvZ/4Thl5gGrCkJYkQWCSnK/M/gkn6v5judNIFbHdUKkP4LkIf8UKwCBcAfaSM9lr6I04BgiEB0onBXuhYEC8vr206qCEFZSAlmgZawQTIEgLS8c6rL+B8JFIBcbUBgDLArD69guqwpC2AUVCNLwrO/ctHLpgAdLIEj3L3CYlqkJiBOBXGxA4Qx3LwyEjVfRHrCqIIQVWSDY8ngpl++93chz8vKkCfegsixXlfImENwJtLfrPngKfAN58HJqtbUM3YB4ZOt6/mVRIAhba45nXrQCQYF7jIlCWG8V7QGrCkKYI4Hwo0L3tCj40Sq6yEBF3+KW/6/BrFgIbZpb/vwO4SoVXWSgHEPlDpJnjmfiGMUyAV/QgRPlxSz7FJUoFB7p+ph7QYBfFRQUVFWH8wDSBCwQBuzdB1seATvzCF07OnF05OPRXETYQ/wvb5Wnmcjf53rmyOtq9/zBkyjLsYjTyrUoUwEhfUgIBPuTzPGKuxE+XL9Op8S5ucwXxqODkU+HYnuvwhdjcfLB5EJ1KEvgooskENhaidIJc1UWXqHetAf0AhXpPEbvuoNndIGd7bxaToTsDcg7JASC/GJwnKKOGNZpjMVCvvw2fy+HY/sTjnu9igoeilMgOOmPcBG202ZaVRDCHAuEKxP2lmtr+KBPgTBQPi79EKfEOfkUCAP5z7ZKrxPXV+oFwsBxzIuqFoWGQPB7hlvcORUVPBSjQHhQoc/xWFYVhDDHAmHgGrhJ4u9LTUcC4SYO8vf7WxOcjyOBwBnLw9ZYttqdZUUgan2THWa7AGkIBMdxf4jypYoKHoItEJzkaeQ51+nkb1YVhDC/BMLIyMjojnQeb8Zt6EggDHZi2E/ha3PLwyth60ggOlBmPGzfY9BoWREIg8uRjweaV8fyl+YmVgz29TLjUddB/0yDC6g/Mh5VVKJQhoLtVLaOwXcZ97y4k6ui/QavFYhr4s6vS57u9NcJGFzBYFvwWqs8zYSNo9ne3cAff7UCR+r5cCdUxfkN5MOP3M3n5DF41Kr8YefX2u0o7yRzevYpFWUJdVdu56Qc3Yk0Lo/BsR8OXumktSIQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoGgrOGSS/4foGS8YOq1ZfQAAAAASUVORK5CYII=",
        "companyContactPersonName": "Test Test",
        "companyEmail": "stacy@example.com",
        "certificateNumber": "CT 001",
        "purchaseOrder": "PO 123",
        "invoiceNumber": "IN 456",
        "authorizingPartyName": "Stacy Slater",
        "authorizingPartyTitle": "Chief Quality Assurance Officer",
        "authorizingPartyDate": "February 19, 2020",
        "manufacturerLocationCompanyName": "Steel Inc.",
        "manufacturerLocationStreetAddress": "3260 46 Ave SE #30",
        "manufacturerLocationAddressLocality": "Calgary",
        "manufacturerLocationAddressRegion": "AB T2B 3K7",
        "manufacturerLocationPostalCode": "",
        "manufacturerLocationAddressCountry": "Canada",
        "customerLocationCompanyName": "Nucor Steel Jewett",
        "customerLocationStreetAddress": "U.S. 79",
        "customerLocationAddressLocality": "Jewett",
        "customerLocationAddressRegion": "TX",
        "customerLocationPostalCode": "",
        "customerLocationAddressCountry": "USA",
        "additionalRemarks": "Product is coated for high temperatures. STEEL-IT High Temp coatings are intended for use where surface temperatures reach above 200°F, such as the external surfaces of industrial ovens, certain types of piping used in chemical and other manufacturing, and more. Customers choose which high temp coating is right for them based on whether USDA approval is required; whether the surface will be exposed to corrosive chemicals; or whether the surface will be exposed to sunlight or other sources of ultraviolet radiation.",
        "productDescription": "SS490 steel is a structural hot Rolled steel in the form of plates, sheets & strips for general structural applications. SS490 is a material grade and designation defined in JIS G 3101 standard. JIS G 3101 is a Japanese material standard for hot Rolled steel plates, sheets, strips for general structural usage. The structural quality hot rolled SS490 steel is more reliable in its tensile strength than SS400 steel...",
        "chemicalProperties": {
          "columns": [
            {
              "title": "Heat Number",
              "field": "heatNumber"
            },
            {
              "title": "C",
              "field": "C"
            },
            {
              "title": "Si",
              "field": "Si"
            },
            {
              "title": "P",
              "field": "P"
            },
            {
              "title": "S",
              "field": "S"
            },
            {
              "title": "V",
              "field": "V"
            },
            {
              "title": "Cr",
              "field": "Cr"
            },
            {
              "title": "Mn",
              "field": "Mn"
            },
            {
              "title": "Ni",
              "field": "Ni"
            },
            {
              "title": "Cu",
              "field": "Cu"
            },
            {
              "title": "Mo",
              "field": "Mo"
            },
            {
              "title": "Sn",
              "field": "Sn"
            }
          ],
          "rows": [
            {
              "heatNumber": "404012",
              "C": ".1"
            },
            {
              "heatNumber": "387230",
              "C": ".4"
            }
          ]
        },
        "mechanicalProperties": {
          "columns": [
            {
              "title": "Heat Number",
              "field": "heatNumber"
            },
            {
              "title": "Item Description",
              "field": "description"
            },
            {
              "title": "Quantity",
              "field": "quantity"
            },
            {
              "title": "Dimension",
              "field": "dimension"
            },
            {
              "title": "Net Weight (Kg)",
              "field": "weight"
            },
            {
              "title": "Yield to Tensile Ratio",
              "field": "yieldToTensileRatio"
            },
            {
              "title": "Yield Strength (PSI)",
              "field": "yieldStrength"
            },
            {
              "title": "Tensile Strength (PSI)",
              "field": "tensileStrength"
            },
            {
              "title": "Elongation (%)",
              "field": "elongation"
            },
            {
              "title": "CHARPY IMPACT Temp (C)",
              "field": "charpyImpactTempDegreesC"
            },
            {
              "title": "CHARPY IMPACT Energy (J)",
              "field": "charpyImpactEnergyJoules"
            }
          ],
          "rows": [
            {
              "description": "Hot Rolled Steel Pipe",
              "quantity": "2",
              "heatNumber": "404012",
              "dimension": "203.2 mm dia. x 5609 + 5663 mm (8\" dia.)",
              "weight": "2900.27",
              "yieldToTensileRatio": "0.73",
              "yieldStrength": "52000",
              "tensileStrength": "71000",
              "elongation": "27"
            },
            {
              "description": "Cold Rolled Steel Bar",
              "quantity": "500",
              "heatNumber": "387230",
              "dimension": "203.2 mm dia. x 5609 + 5663 mm",
              "weight": "2900.27",
              "yieldToTensileRatio": "0.72",
              "yieldStrength": "55000",
              "tensileStrength": "76000",
              "elongation": "27"
            }
          ]
        },
        "standardSpecifications": [
          {
            "title": "JIS G 3101",
            "description": "Rolled steels for general structure",
            "isoCode": "JIS G 3101"
          }
        ],
        "standardGrades": [
          {
            "title": "SUS201",
            "description": "SUS201"
          }
        ],
        "proprietarySpecifications": [
          {
            "title": "ASTM-51",
            "description": "ASTM-51"
          }
        ],
        "proprietaryGrades": [
          {
            "title": "BF-4122",
            "description": "BF-4122"
          }
        ]
      }
    },
    "proof": {
      "type": "Ed25519Signature2018",
      "created": "2020-04-27T16:33:36Z",
      "verificationMethod": "did:elem:ropsten:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..W98hFRglzPdcFGG2kx4wL68IcPjSemwWLyeYhcUo6-e5ZAwkBgNoX7gUGg4_xvZnhscGv4fTBzJYkxRv1GdpAQ"
    }
  }
`

	publicKeyBytes := base58.Decode("kw41Mbj9jVnNDrrQPMEK6iZzG5cjSjkxmr9u2V6igxL")

	vc, _, err := NewCredential([]byte(vcJSON),
		WithPublicKeyFetcher(SingleKey(publicKeyBytes, "Ed25519Signature2018")),
		WithEmbeddedSignatureSuites(ed25519signature2018.New(
			suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))),
		WithJSONLDOnlyValidRDF(),
		WithStrictValidation())

	require.NoError(t, err)
	require.NotNil(t, vc)
}

//nolint:lll
func TestNewCredential_ProofCreatedWithMillisec(t *testing.T) {
	vcJSON := `
	{
	       "issuanceDate": "2020-03-10T04:24:12.164Z",
	       "credentialSubject": {
	         "degree": {
	           "name": "Bachelor of Science and Arts",
	           "type": "BachelorDegree"
	         },
	         "id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
	       },
	       "id": "http://example.gov/credentials/3732",
	       "type": [
	         "VerifiableCredential",
	         "UniversityDegreeCredential"
	       ],
	       "@context": [
	         "https://www.w3.org/2018/credentials/v1",
	         "https://www.w3.org/2018/credentials/examples/v1"
	       ],
	       "issuer": {
	         "id": "did:key:z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN"
	       },
	       "proof": {
	         "created": "2020-05-04T14:30:37.972Z",
	         "proofPurpose": "assertionMethod",
	         "type": "Ed25519Signature2018",
	         "verificationMethod": "did:key:z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN#z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN",
	         "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..SVA8JpQQU9-XP9mlEB-V0TVeX0V7d_jDImQyXrV1-SzfOTP7M6CERVmj7ppAAed1CgIQceIoiIZ8sUN3n_0UDg"
	       }
	     }
	`

	publicKeyBytes := base58.Decode("DNwKNoq5MnZ185AyatKe3kT7MMCDD7R2PeNDV6FndMkz")

	vc, _, err := NewCredential([]byte(vcJSON),
		WithPublicKeyFetcher(SingleKey(publicKeyBytes, "Ed25519Signature2018")),
		WithEmbeddedSignatureSuites(ed25519signature2018.New(
			suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))),
		WithStrictValidation())

	require.NoError(t, err)
	require.NotNil(t, vc)
}

func TestNewCredentialWithSeveralLinkedDataProofs(t *testing.T) {
	r := require.New(t)

	ed25519PubKey, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	r.NotNil(ed25519PubKey)

	ed25519SigSuite := ed25519signature2018.New(
		suite.WithSigner(getEd25519TestSigner(ed25519PrivKey)),
		suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

	vc, _, err := NewCredential([]byte(validCredential))
	r.NoError(err)

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		SignatureRepresentation: SignatureProofValue,
		Suite:                   ed25519SigSuite,
		VerificationMethod:      "did:example:123456#key1",
	})
	r.NoError(err)

	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaSigSuite := jsonwebsignature2020.New(
		suite.WithSigner(getEcdsaP256TestSigner(ecdsaPrivKey)),
		suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier()))

	err = vc.AddLinkedDataProof(&LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		SignatureRepresentation: SignatureJWS,
		Suite:                   ecdsaSigSuite,
		VerificationMethod:      "did:example:123456#key2",
	})
	r.NoError(err)

	vcBytes, err := json.Marshal(vc)
	r.NoError(err)
	r.NotEmpty(vcBytes)

	vcWithLdp, _, err := NewCredential(vcBytes,
		WithEmbeddedSignatureSuites(ed25519SigSuite, ecdsaSigSuite),
		WithPublicKeyFetcher(func(issuerID, keyID string) (*sigverifier.PublicKey, error) {
			switch keyID {
			case "#key1":
				return &sigverifier.PublicKey{
					Type:  "Ed25519Signature2018",
					Value: ed25519PubKey,
				}, nil

			case "#key2":
				return &sigverifier.PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: elliptic.Marshal(ecdsaPrivKey.Curve, ecdsaPrivKey.X, ecdsaPrivKey.Y),
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Algorithm: "ES256",
							Key:       &ecdsaPrivKey.PublicKey,
						},
						Crv: "P-256",
						Kty: "EC",
					},
				}, nil
			}

			return nil, errors.New("unsupported keyID")
		}))
	r.NoError(err)
	r.Equal(vc, vcWithLdp)
}

func createLocalCrypto() crypto.Crypto {
	lKMS := createKMS()

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		panic("failed to create tinkcrypto")
	}

	return &LocalCrypto{
		Crypto:   tinkCrypto,
		localKMS: lKMS,
	}
}

// LocalCrypto defines a verifier which is based on Local KMS and Crypto
// which uses keyset.Handle as input for verification.
type LocalCrypto struct {
	*tinkcrypto.Crypto
	localKMS *localkms.LocalKMS
}

func (t *LocalCrypto) Verify(sig, msg []byte, kh interface{}) error {
	pubKey, ok := kh.(*sigverifier.PublicKey)
	if !ok {
		return errors.New("bad key handle format")
	}

	kmsKeyType, err := mapPublicKeyToKMSKeyType(pubKey)
	if err != nil {
		return err
	}

	handle, err := t.localKMS.PubKeyBytesToHandle(pubKey.Value, kmsKeyType)
	if err != nil {
		return err
	}

	return t.Crypto.Verify(sig, msg, handle)
}

func mapPublicKeyToKMSKeyType(pubKey *sigverifier.PublicKey) (kms.KeyType, error) {
	switch pubKey.Type {
	case "Ed25519Signature2018":
		return kms.ED25519Type, nil
	case "JwsVerificationKey2020":
		return mapJWKToKMSKeyType(pubKey.JWK)
	default:
		return "", fmt.Errorf("unsupported key type: %s", pubKey.Type)
	}
}

func mapJWKToKMSKeyType(jwk *jose.JWK) (kms.KeyType, error) {
	switch jwk.Kty {
	case "OKP":
		return kms.ED25519Type, nil
	case "EC":
		switch jwk.Crv {
		case "P-256":
			return kms.ECDSAP256TypeIEEEP1363, nil
		case "P-384":
			return kms.ECDSAP384TypeIEEEP1363, nil
		case "P-521":
			return kms.ECDSAP521TypeIEEEP1363, nil
		}
	}

	return "", fmt.Errorf("unsupported JWK: %v", jwk)
}

func createKMS() *localkms.LocalKMS {
	p := mockkms.NewProvider(storage.NewMockStoreProvider(), &noop.NoLock{})

	k, err := localkms.New("local-lock://custom/master/key/", p)
	if err != nil {
		panic(err)
	}

	return k
}

func TestCredential_AddLinkedDataProof(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	t.Run("Add a valid JWS Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		r.NoError(err)

		originalVCMap, err := toMap(vc)
		r.NoError(err)

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureJWS,
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
			VerificationMethod:      "did:example:xyz#key-1",
			Challenge:               uuid.New().String(),
			Domain:                  "issuer.service.com",
			Purpose:                 "authentication",
		})
		r.NoError(err)

		vcMap, err := toMap(vc)
		r.NoError(err)

		r.Contains(vcMap, "proof")
		vcProof := vcMap["proof"]
		vcProofMap, ok := vcProof.(map[string]interface{})
		r.True(ok)
		r.Contains(vcProofMap, "created")
		r.Contains(vcProofMap, "jws")
		r.Contains(vcProofMap, "challenge")
		r.Contains(vcProofMap, "domain")
		r.Contains(vcProofMap, "verificationMethod")
		r.Contains(vcProofMap, "proofPurpose")
		r.Equal("Ed25519Signature2018", vcProofMap["type"])
		r.Equal("authentication", vcProofMap["proofPurpose"])

		// check that only "proof" element was added as a result of AddLinkedDataProof().
		delete(vcMap, "proof")
		r.Equal(originalVCMap, vcMap)
	})

	t.Run("Add invalid Linked Data proof to VC", func(t *testing.T) {
		vc, _, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		vc.CustomFields = map[string]interface{}{
			"invalidField": make(chan int),
		}

		err = vc.AddLinkedDataProof(&LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			SignatureRepresentation: SignatureProofValue,
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
		})
		r.Error(err)

		vc.CustomFields = nil
		ldpContextWithMissingSignatureType := &LinkedDataProofContext{
			Suite:                   ed25519signature2018.New(suite.WithSigner(getEd25519TestSigner(privKey))),
			SignatureRepresentation: SignatureProofValue,
		}

		err = vc.AddLinkedDataProof(ldpContextWithMissingSignatureType)
		r.Error(err)
	})
}
