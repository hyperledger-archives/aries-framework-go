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
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
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
func TestNewCredentialFromLinkedDataProof_Ed25519Signature2018_Transmute(t *testing.T) {
	r := require.New(t)

	vcFromTransmute := `
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

	pubKeyBytes := base58.Decode("DqS5F3GVe3rCxucgi4JBNagjv4dKoHc8TDLDw9kR58Pz")

	sigSuite := ed25519signature2018.New(
		suite.WithVerifier(suite.NewCryptoVerifier(createLocalCrypto())))

	vcWithLdp, _, err := NewCredential([]byte(vcFromTransmute),
		WithEmbeddedSignatureSuites(sigSuite),
		WithPublicKeyFetcher(SingleKey(pubKeyBytes, "Ed25519Signature2018")))
	r.NoError(err)
	r.NotNil(t, vcWithLdp)
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

	// TODO replace ecdsa.GenerateKey with KMS.Create(kms.ECDSAP256TypeIEEE1363) and use localkms and Crypto for signing
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

	t.Logf("vc with 2 LDP: %s\n", string(vcBytes))

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
			return kms.ECDSAP256TypeIEEE1363, nil
		case "P-384":
			return kms.ECDSAP384TypeIEEE1363, nil
		case "P-521":
			return kms.ECDSAP521TypeIEEE1363, nil
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
