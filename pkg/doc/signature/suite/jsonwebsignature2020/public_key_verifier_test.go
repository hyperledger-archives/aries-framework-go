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
	"encoding/asn1"
	"fmt"
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
				Key:       &privKey.PublicKey,
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
				privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err)

				pubKeyBytes = elliptic.Marshal(tc.curve, privKey.X, privKey.Y)
				pubKey = &sigverifier.PublicKey{
					Type:  "JwsVerificationKey2020",
					Value: pubKeyBytes,
					JWK: &jose.JWK{
						JSONWebKey: gojose.JSONWebKey{
							Key:       &privKey.PublicKey,
							Algorithm: tc.algorithm,
						},
						Crv: tc.curveName,
						Kty: "EC",
					},
				}

				v := NewPublicKeyVerifier()
				signature, err := getECSignature(privKey, msg, tc.hash)
				require.NoError(t, err)

				err = v.Verify(pubKey, msg, signature)
				require.NoError(t, err)
			})
		}
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
			JSONWebKey: gojose.JSONWebKey{Key: publicKey},
			Kty:        "OKP",
			Crv:        "Ed25519",
		},
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
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

	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}

func getECSignature(privKey *ecdsa.PrivateKey, payload []byte, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		return nil, err
	}

	// use DER format of signature
	ecdsaSig := sigverifier.NewECDSASignature(r, s)

	ret, err := asn1.Marshal(*ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("asn.1 encoding failed: %w", err)
	}

	return ret, nil
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
