/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
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

		msg       = []byte("message to sign")
		signature = []byte("signature")

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

	err := verifier.Verify(publicKey, msg, signature)
	require.NoError(t, err)

	t.Run("check public key type", func(t *testing.T) {
		publicKey.Type = "invalid TestType"

		err = verifier.Verify(publicKey, msg, signature)
		require.Error(t, err)
		require.EqualError(t, err, "a type of public key is not 'TestType'")

		publicKey.Type = "TestType"
	})

	t.Run("match JWK key type", func(t *testing.T) {
		publicKey.JWK.Kty = "invalid kty"

		err = verifier.Verify(publicKey, msg, signature)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Kty = "kty"
	})

	t.Run("match JWK curve", func(t *testing.T) {
		publicKey.JWK.Crv = "invalid crv"

		err = verifier.Verify(publicKey, msg, signature)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Crv = "crv"
	})

	t.Run("match JWK algorithm", func(t *testing.T) {
		publicKey.JWK.Algorithm = "invalid alg"

		err = verifier.Verify(publicKey, msg, signature)
		require.Error(t, err)
		require.EqualError(t, err, "verifier does not match JSON Web Key")

		publicKey.JWK.Algorithm = "alg"
	})

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, signature)
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

		msg       = []byte("message to sign")
		signature = []byte("signature")

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

	err := verifier.Verify(publicKey, msg, signature)
	require.NoError(t, err)

	publicKey.JWK.Kty = "invalid kty"
	err = verifier.Verify(publicKey, msg, signature)
	require.Error(t, err)
	require.EqualError(t, err, "no matching verifier found")

	publicKey.JWK.Kty = "kty"

	signatureVerifier.verifyResult = errors.New("invalid signature")
	err = verifier.Verify(publicKey, msg, signature)
	require.Error(t, err)
	require.EqualError(t, err, "invalid signature")
}

func TestNewEd25519SignatureVerifier(t *testing.T) {
	v := NewEd25519SignatureVerifier()
	require.NotNil(t, v)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig := ed25519.Sign(privateKey, msg)
	pubKey := &PublicKey{
		Type:  kms.ED25519,
		Value: publicKey,
	}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid public key type
	err = v.Verify(&PublicKey{
		Type:  kms.ED25519,
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

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig := getRSASignature(privKey, msg)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pubKey := &PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "PS256",
			},
			Kty: "RSA",
		},
		Value: pubKeyBytes,
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
				privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err)

				pubKeyBytes := elliptic.Marshal(tc.curve, privKey.X, privKey.Y)
				pubKey := &PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: pubKeyBytes,
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Algorithm: tc.algorithm,
						},
						Crv: tc.curveName,
						Kty: "EC",
					},
				}

				signature := getECSignature(privKey, msg, tc.hash)

				err = tc.sVerifier.Verify(pubKey, msg, signature)
				require.NoError(t, err)
			})
		}
	})

	v := NewECDSAES256SignatureVerifier()
	require.NotNil(t, v)

	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	t.Run("invalid public key", func(t *testing.T) {
		signature := getECSignature(privKey, msg, crypto.SHA256)

		verifyError := v.Verify(&PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: []byte("invalid public key"),
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
				},
				Crv: "P-256",
				Kty: "EC",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid public key")
	})

	t.Run("invalid signature", func(t *testing.T) {
		pubKeyBytes := elliptic.Marshal(curve, privKey.X, privKey.Y)
		pubKey := &PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: pubKeyBytes,

			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
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

	t.Run("unsupported elliptic curve", func(t *testing.T) {
		verifyError := v.Verify(&PublicKey{
			JWK: &jose.JWK{
				Crv: "invalid crv",
			},
		}, msg, []byte("some signature"))
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: unsupported elliptic curve 'invalid crv'")
	})
}

type testSignatureVerifier struct {
	baseSignatureVerifier

	verifyResult error
}

func (v testSignatureVerifier) Verify(*PublicKey, []byte, []byte) error {
	return v.verifyResult
}

func getRSASignature(privKey *rsa.PrivateKey, payload []byte) []byte {
	hasher := crypto.SHA256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		panic(err)
	}

	return signature
}

func getECSignature(privKey *ecdsa.PrivateKey, payload []byte, hash crypto.Hash) []byte {
	hasher := hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		panic(err)
	}

	curveBits := privKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...)
}
