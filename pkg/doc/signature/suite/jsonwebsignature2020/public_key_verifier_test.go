/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestPublicKeyVerifier_Verify_EC(t *testing.T) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")

	pubKeyBytes := elliptic.Marshal(curve, privKey.X, privKey.Y)
	pubKey := &sigverifier.PublicKey{
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

	v := &PublicKeyVerifier{}
	signature := getECSignature(privKey, msg)

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			curve     elliptic.Curve
			curveName string
			algorithm string
		}{
			{
				curve:     elliptic.P256(),
				curveName: "P-256",
				algorithm: "ES256",
			},
			{
				curve:     elliptic.P384(),
				curveName: "P-384",
				algorithm: "ES384",
			},
			{
				curve:     elliptic.P521(),
				curveName: "P-521",
				algorithm: "ES521",
			},
			{
				curve:     btcec.S256(),
				curveName: "secp256k1",
				algorithm: "ES256K",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.curveName, func(t *testing.T) {
				privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err)

				pubKeyBytes = elliptic.Marshal(tc.curve, privKey.X, privKey.Y)
				pubKey = &sigverifier.PublicKey{
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

				v = &PublicKeyVerifier{}
				signature = getECSignature(privKey, msg)

				err = v.Verify(pubKey, msg, signature)
				require.NoError(t, err)
			})
		}
	})

	t.Run("undefined JWK", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: pubKeyBytes,
		}, msg, signature)
		require.Error(t, verifyError)
		require.Equal(t, verifyError, ErrJWKNotPresent)
	})

	t.Run("JWK is invalid type", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "Ed25519Signature2018",
			Value: pubKeyBytes,
			JWK:   &jose.JWK{},
		}, msg, signature)
		require.Error(t, verifyError)
		require.Equal(t, verifyError, ErrTypeNotJwsVerificationKey2020)
	})

	t.Run("JWK with unsupported key type", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: pubKeyBytes,
			JWK: &jose.JWK{
				Kty: "unknown",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "unsupported key type: unknown")
	})

	t.Run("unsupported curve", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "JwsVerificationKey2020",
			Value: pubKeyBytes,
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256",
				},
				Crv: "unsupported",
				Kty: "EC",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: unsupported elliptic curve 'unsupported'")
	})

	t.Run("invalid public key", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
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
		verifyError := v.Verify(pubKey, msg, []byte("signature of invalid size"))
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature size")

		emptySig := make([]byte, 64)
		verifyError = v.Verify(pubKey, msg, emptySig)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: invalid signature")
	})
}

func TestPublicKeyVerifier_Verify_Ed25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig := ed25519.Sign(privateKey, msg)

	pubKey := &sigverifier.PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			Kty: "OKP",
			Crv: "Ed25519",
		},
		Value: publicKey,
	}
	v := &PublicKeyVerifier{}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid signature")

	// invalid public key
	pubKey.Value = []byte("invalid-key")
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "ed25519: invalid key")

	// unsupported OKP algorithm - must be EdDSA if defined
	pubKey.Value = publicKey
	pubKey.JWK.Algorithm = "unknown"
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported OKP algorithm: unknown")
}

func TestPublicKeyVerifier_Verify_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig := getRSASignature(privKey, msg)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pubKey := &sigverifier.PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "PS256",
			},
			Kty: "RSA",
		},
		Value: pubKeyBytes,
	}

	v := &PublicKeyVerifier{}

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)

	// invalid signature
	err = v.Verify(pubKey, msg, []byte("invalid signature"))
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid signature")

	// unsupported RSA algorithm
	pubKey.JWK.Algorithm = "RS512"
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "unsupported RSA algorithm: RS512")

	// invalid public key
	pubKey.JWK.Algorithm = "PS256"
	pubKey.Value = []byte("invalid-key")
	err = v.Verify(pubKey, msg, msgSig)
	require.Error(t, err)
	require.EqualError(t, err, "rsa: invalid public key")
}

func getECSignature(privKey *ecdsa.PrivateKey, payload []byte) []byte {
	hasher := crypto.SHA256.New()

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

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...)
}

func copyPadded(source []byte, size int) []byte {
	dest := make([]byte, size)
	copy(dest[size-len(source):], source)

	return dest
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
