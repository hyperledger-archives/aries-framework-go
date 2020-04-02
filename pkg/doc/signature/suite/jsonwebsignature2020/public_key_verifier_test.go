/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestPublicKeyVerifierP256_Verify(t *testing.T) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")

	pubKeyBytes := elliptic.Marshal(curve, privKey.X, privKey.Y)
	pubKey := &sigverifier.PublicKey{
		Type:  kms.ED25519,
		Value: pubKeyBytes,

		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "ES256",
			},
			Crv: "P-256",
			Kty: "EC",
		},
	}

	v := &PublicKeyVerifierEC{}
	signature := getSignature(privKey, msg)

	t.Run("happy path", func(t *testing.T) {
		verifyError := v.Verify(pubKey, msg, signature)
		require.NoError(t, verifyError)
	})

	t.Run("undefined JWK", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  kms.ED25519,
			Value: pubKeyBytes,
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "JWK is not defined")
	})

	t.Run("unsupported curve", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  kms.ED25519,
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
			Type:  kms.ED25519,
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

func TestPublicKeyVerifier_Verify(t *testing.T) {
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

			msg := []byte("test message")

			pubKeyBytes := elliptic.Marshal(tc.curve, privKey.X, privKey.Y)
			pubKey := &sigverifier.PublicKey{
				Type:  kms.ED25519,
				Value: pubKeyBytes,
				JWK: &jose.JWK{
					JSONWebKey: gojose.JSONWebKey{
						Algorithm: tc.algorithm,
					},
					Crv: tc.curveName,
					Kty: "EC",
				},
			}

			v := &PublicKeyVerifierEC{}
			signature := getSignature(privKey, msg)

			err = v.Verify(pubKey, msg, signature)
			require.NoError(t, err)
		})
	}
}

func getSignature(privKey *ecdsa.PrivateKey, payload []byte) []byte {
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
