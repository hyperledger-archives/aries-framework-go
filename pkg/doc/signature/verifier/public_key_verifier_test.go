/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

func TestNewPublicKeyVerifier(t *testing.T) {
	var (
		publicKey = &PublicKey{
			Type: "TestType",
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "alg",
				},
				Kty: "kty",
				Crv: "crv",
			},
		}

		msg    = []byte("message to sign")
		msgSig = []byte("signature")

		signatureVerifier = &testSignatureVerifier{
			baseSignatureVerifier: baseSignatureVerifier{
				keyType:   "kty",
				curve:     "crv",
				algorithm: "alg",
			},
			verifyResult: nil,
		}
	)

	verifier := NewPublicKeyVerifier(signatureVerifier, WithExactPublicKeyType("TestType"))
	require.NotNil(t, verifier)

	err := verifier.Verify(publicKey, msg, msgSig)
	require.NoError(t, err)

	t.Run("check public key type", func(t *testing.T) {
		publicKey.Type = "invalid TestType"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "a type of public key is not 'TestType'")

		publicKey.Type = "TestType"
	})

	t.Run("match JWK key type", func(t *testing.T) {
		publicKey.JWK.Kty = "invalid kty"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Kty = "kty"
	})

	t.Run("match JWK curve", func(t *testing.T) {
		publicKey.JWK.Crv = "invalid crv"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Crv = "crv"
	})

	t.Run("match JWK algorithm", func(t *testing.T) {
		publicKey.JWK.Algorithm = "invalid alg"

		err = verifier.Verify(publicKey, msg, msgSig)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Algorithm = "alg"
	})

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "invalid signature")
}

func TestNewCompositePublicKeyVerifier(t *testing.T) {
	var (
		publicKey = &PublicKey{
			Type: "TestType",
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "alg",
				},
				Kty: "kty",
				Crv: "crv",
			},
		}

		msg    = []byte("message to sign")
		msgSig = []byte("signature")

		signatureVerifier = &testSignatureVerifier{
			baseSignatureVerifier: baseSignatureVerifier{
				keyType:   "kty",
				curve:     "crv",
				algorithm: "alg",
			},
			verifyResult: nil,
		}
	)

	verifier := NewCompositePublicKeyVerifier([]SignatureVerifier{signatureVerifier},
		WithExactPublicKeyType("TestType"))
	require.NotNil(t, verifier)

	err := verifier.Verify(publicKey, msg, msgSig)
	require.NoError(t, err)

	publicKey.JWK.Kty = "invalid kty"
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "no matching verifier found")

	publicKey.JWK.Kty = "kty"

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "invalid signature")
}

func TestNewEd25519SignatureVerifier(t *testing.T) {
	v := NewEd25519SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.ED25519Type)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &PublicKey{
		Type:  kmsapi.ED25519,
		Value: signer.PublicKeyBytes(),
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(&PublicKey{
		Type:  kmsapi.ED25519,
		Value: []byte("invalid-key"),
	}, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid key")

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid signature")
}

func TestNewRSAPS256SignatureVerifier(t *testing.T) {
	v := NewRSAPS256SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.RSAPS256Type)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "PS256",
			},
			Kty: "RSA",
		},
		Value: signer.PublicKeyBytes(),
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid signature")

	// invalid public key
	pubKey.Value = []byte("invalid-key")
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")
}

func TestNewECDSAES256SignatureVerifier(t *testing.T) {
	msg := []byte("test message")

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			sVerifier SignatureVerifier
			curve     elliptic.Curve
			curveName string
			algorithm string
			hash      crypto.Hash
		}{
			{
				sVerifier: NewECDSAES256SignatureVerifier(),
				curve:     elliptic.P256(),
				curveName: "P-256",
				algorithm: "ES256",
				hash:      crypto.SHA256,
			},
			{
				sVerifier: NewECDSAES384SignatureVerifier(),
				curve:     elliptic.P384(),
				curveName: "P-384",
				algorithm: "ES384",
				hash:      crypto.SHA384,
			},
			{
				sVerifier: NewECDSAES521SignatureVerifier(),
				curve:     elliptic.P521(),
				curveName: "P-521",
				algorithm: "ES521",
				hash:      crypto.SHA512,
			},
			{
				sVerifier: NewECDSASecp256k1SignatureVerifier(),
				curve:     btcec.S256(),
				curveName: "secp256k1",
				algorithm: "ES256K",
				hash:      crypto.SHA256,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.curveName, func(t *testing.T) {
				keyType, err := signature.MapECCurveToKeyType(tc.curve)
				require.NoError(t, err)

				signer, err := newCryptoSigner(keyType)
				require.NoError(t, err)

				pubKey := &PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: signer.PublicKeyBytes(),
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Algorithm: tc.algorithm,
							Key:       signer.PublicKey(),
						},
						Crv: tc.curveName,
						Kty: "EC",
					},
				}

				msgSig, err := signer.Sign(msg)
				require.NoError(t, err)

				err = tc.sVerifier.Verify(pubKey, msg, msgSig)
				require.NoError(t, err)
			})
		}
	})

	v := NewECDSAES256SignatureVerifier()
	require.NotNil(t, v)

	signer, err := newCryptoSigner(kmsapi.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	t.Run("verify with public key bytes", func(t *testing.T) {
		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),
		}, msg, msgSig)

		require.NoError(t, verifyError)
	})

	t.Run("invalid public key", func(t *testing.T) {
		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: []byte("invalid public key"),
		}, msg, msgSig)

		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: create JWK from public key bytes: invalid public key")
	})

	t.Run("invalid public key type", func(t *testing.T) {
		ed25519Key := &ed25519.PublicKey{}

		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
					Key:       ed25519Key,
				},
				Crv: "P-256",
				Kty: "EC",
			},
		}, msg, msgSig)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid public key type")
	})

	t.Run("invalid signature", func(t *testing.T) {
		pubKey := &PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: signer.PublicKeyBytes(),

			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
					Key:       signer.PublicKey(),
				},
				Crv: "P-256",
				Kty: "EC",
			},
		}

		verifyError := v.Verify(pubKey, msg, []byte("signature of invalid size"))
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature size")

		emptySig := make([]byte, 64)
		verifyError = v.Verify(pubKey, msg, emptySig)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature")
	})
}

//nolint:lll
func TestNewBBSG2SignatureVerifier(t *testing.T) {
	pkBase64 := "h/rkcTKXXzRbOPr9UxSfegCbid2U/cVNXQUaKeGF7UhwrMJFP70uMH0VQ9+3+/2zDPAAjflsdeLkOXW3+ShktLxuPy8UlXSNgKNmkfb+rrj+FRwbs13pv/WsIf+eV66+"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := `o/79UazZRsf3y35mZ8kT6hx2M2R1fGgj2puotSqeLiha5MGRmqHLx1JAQsG3JlJeW5n56Gg+xUKaDPfzyimi0V9ECloPIBJY+dIMjQE15PFAk+/wtnde9QY8cZOmTIiI56HuN6DwADIzo3BLwkL2RQ==`
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2020-10-07T16:38:09Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:489398593#test> .
<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgokJggg==> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .
`

	verifier := NewBBSG2SignatureVerifier()
	err = verifier.Verify(&PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pkBytes,
	}, []byte(msg), sigBytes)

	require.NoError(t, err)
}

//nolint:lll
func TestNewBBSG2SignatureProofVerifier(t *testing.T) {
	pubKeyBase58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
	pubKeyBytes := base58.Decode(pubKeyBase58)

	sigBase64 := "ABkB/wbvjc59cvFAxJhH2E3fWe2EZWWh2iBEfephMQ1JSgZJwnVFQ8ch4TYQx2lI6clKrvaIsN7CxOUIGnwxPvuLZHW9tj8SlNm7hI9xoW35KwT9ZjoiQyKv91HnLQD+7CLzFxjrlJNtPCGtYtc/dvQWg0+Bnlbj1g6FwJhDx8BdPxh/FscXnHWeCv6hcGEYdsScMdmMAAAAdIPNXrxeW318emMXwyCuBRx2Dx2HwYyxkrObIRfltrewtA0+Cez70ly4gbhEO9qiuwAAAAII8cfSf8NSPa1YgWK9wP7O4ZSB5raj++v3aJuODprBNBA2EpmNmYAoVQ4SYnFiZnvevOOppbaoNPwZagiq04LdihnG+5GP6PTm9vbEKII7oe/2yutHlrSboZ6dYkm2+BYf//ZWb8b3COuD1J+gcKfRAAAACV0EYp/ekOsDonqefgUbssbEa1f7/kwItqw4vKpOekgKEkY8i+/Xm5gZVnpDeNDSNVKB/RVIBHrBIcxmtdMZZzhlkx4VJhJ6F8JvKzo3HniGEL/gC4Sxp/r8YXUxZDcFXhvzL+2C96VJSmlqqEe7gMRKluCNyADqV7+Kz+xdC7xfE4xsyo8JLWe/QnLRd/FtenkCKa3e8flyniMiq27sy1I8Pfsuy2SZGieLND5PgKlKlZXVbdxMh8t6slLTZx1wK1MhfLGfiQIq7x2x544qXoW4QK0eJdv41fp2VtiF1lbWVRY+uJAiZg5ov/1hJg4lkE/V/AGoNRbC/LRilp67+HVb4W2R6FnD4JFKbEJD7lIVrzIOn+JocsRNOzPx5pWQrA=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2020-12-06T19:23:10Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:example:489398593#test> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/identifier> "83627465" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:example:489398593> .
`

	verifier := NewBBSG2SignatureProofVerifier([]byte("nonce"))
	err = verifier.Verify(&PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pubKeyBytes,
	}, []byte(msg), sigBytes)

	require.NoError(t, err)
}

type testSignatureVerifier struct {
	baseSignatureVerifier

	verifyResult error
}

func (v testSignatureVerifier) Verify(*PublicKey, []byte, []byte) error {
	return v.verifyResult
}

func newCryptoSigner(keyType kmsapi.KeyType) (signature.Signer, error) {
	p := mockkms.NewProviderForKMS(storage.NewMockStoreProvider(), &noop.NoLock{})

	localKMS, err := localkms.New("local-lock://custom/main/key/", p)
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return signature.NewCryptoSigner(tinkCrypto, localKMS, keyType)
}
