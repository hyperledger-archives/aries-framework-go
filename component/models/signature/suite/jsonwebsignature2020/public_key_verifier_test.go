/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	signature "github.com/hyperledger/aries-framework-go/component/models/signature/util"
	sigverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestPublicKeyVerifier_Verify_EC(t *testing.T) {
	msg := []byte("test message")

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
				keyType, err := signature.MapECCurveToKeyType(tc.curve)
				require.NoError(t, err)

				signer, err := newCryptoSigner(t, keyType)
				require.NoError(t, err)

				pubKey := &sigverifier.PublicKey{
					Type:  "JsonWebKey2020",
					Value: signer.PublicKeyBytes(),
					JWK: &jwk.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Key:       signer.PublicKey(),
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
	signer, err := newCryptoSigner(t, kmsapi.ED25519Type)
	require.NoError(t, err)

	msg := []byte("test message")
	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: "JsonWebKey2020",
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{Key: signer.PublicKey()},
			Kty:        "OKP",
			Crv:        "Ed25519",
		},
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func TestPublicKeyVerifier_Verify_RSA(t *testing.T) {
	signer, err := newCryptoSigner(t, kmsapi.RSAPS256Type)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &sigverifier.PublicKey{
		Type: "JsonWebKey2020",
		JWK: &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "PS256",
			},
			Kty: "RSA",
		},
		Value: signer.PublicKeyBytes(),
	}

	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func newCryptoSigner(t *testing.T, keyType kmsapi.KeyType) (signature.Signer, error) {
	localKMS, err := createKMS(t)
	if err != nil {
		return nil, err
	}

	tinkCrypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return signature.NewCryptoSigner(tinkCrypto, localKMS, keyType)
}
