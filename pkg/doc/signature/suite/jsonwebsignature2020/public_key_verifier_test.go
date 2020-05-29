/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
)

func TestPublicKeyVerifier_Verify_EC(t *testing.T) {
	curve := elliptic.P256()
	signer, err := signature.NewECDSAP256Signer()
	require.NoError(t, err)

	msg := []byte("test message")

	pubKeyBytes := elliptic.Marshal(curve, signer.PublicKey.X, signer.PublicKey.Y)
	pubKey := &sigverifier.PublicKey{
		Type:  "JwsVerificationKey2020",
		Value: pubKeyBytes,

		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key:       signer.PublicKey,
				Algorithm: "ES256",
			},
			Crv: "P-256",
			Kty: "EC",
		},
	}

	t.Run("happy path", func(t *testing.T) {
		tests := []struct {
			curve     elliptic.Curve
			curveName string
			algorithm string
			hash      crypto.Hash
		}{
			{
				curve:     elliptic.P256(),
				curveName: "P-256",
				algorithm: "ES256",
				hash:      crypto.SHA256,
			},
			{
				curve:     elliptic.P384(),
				curveName: "P-384",
				algorithm: "ES384",
				hash:      crypto.SHA384,
			},
			{
				curve:     elliptic.P521(),
				curveName: "P-521",
				algorithm: "ES521",
				hash:      crypto.SHA512,
			},
			{
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
				signer, err := signature.NewECDSASigner(tc.curve)
				require.NoError(t, err)

				pubKeyBytes = elliptic.Marshal(tc.curve, signer.PublicKey.X, signer.PublicKey.Y)
				pubKey = &sigverifier.PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: pubKeyBytes,
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Key:       signer.PublicKey,
							Algorithm: tc.algorithm,
						},
						Crv: tc.curveName,
						Kty: "EC",
					},
				}

				msgSig, err := signer.Sign(msg)
				require.NoError(t, err)

				v := NewPublicKeyVerifier()
				err = v.Verify(pubKey, msg, msgSig)
				require.NoError(t, err)
			})
		}
	})
}

func TestPublicKeyVerifier_Verify_Ed25519(t *testing.T) {
	signer, err := signature.NewEd25519Signer()
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: "JwsVerificationKey2020",
		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{Key: signer.PublicKey},
			Kty:        "OKP",
			Crv:        "Ed25519",
		},
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func TestPublicKeyVerifier_Verify_RSA(t *testing.T) {
	signer, err := signature.NewPS256Signer()
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKeyBytes := x509.MarshalPKCS1PublicKey(signer.PublicKey)
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

	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
