/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsasecp256k1signature2019

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	btcecPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	ecdsaPrivKey := btcecPrivKey.ToECDSA()

	ecdsaPubKey := &ecdsaPrivKey.PublicKey

	msg := []byte("test message")

	pubKeyBytes := btcecPrivKey.PubKey().SerializeCompressed()

	pubKey := &sigverifier.PublicKey{
		Type:  "EcdsaSecp256k1VerificationKey2019",
		Value: pubKeyBytes,

		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "ES256K",
			},
			Crv: "secp256k1",
			Kty: "EC",
		},
	}

	v := &PublicKeyVerifier{}
	signature := getSignature(&ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaPubKey.Curve,
			X:     ecdsaPubKey.X,
			Y:     ecdsaPubKey.Y,
		},
		D: btcecPrivKey.D,
	}, msg)

	v = &PublicKeyVerifier{}
	signature = getSignature(ecdsaPrivKey, msg)

	err = v.Verify(pubKey, msg, signature)
	require.NoError(t, err)

	t.Run("undefined JWK", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "EcdsaSecp256k1VerificationKey2019",
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
		require.Equal(t, verifyError, ErrTypeNotEcdsaSecp256k1VerificationKey2019)
	})

	t.Run("JWK with unsupported key type", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "EcdsaSecp256k1VerificationKey2019",
			Value: pubKeyBytes,
			JWK: &jose.JWK{
				Kty: "unknown",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "unsupported key type: 'unknown'")
	})

	t.Run("invalid curve", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "EcdsaSecp256k1VerificationKey2019",
			Value: pubKeyBytes,
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256K",
				},
				Crv: "unsupported",
				Kty: "EC",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: not secp256k1 curve: 'unsupported'")
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "EcdsaSecp256k1VerificationKey2019",
			Value: pubKeyBytes,
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES512",
				},
				Crv: "secp256k1",
				Kty: "EC",
			},
		}, msg, signature)
		require.Error(t, verifyError)
		require.EqualError(t, verifyError, "ecdsa: not ES256K EC algorithm: 'ES512'")
	})

	t.Run("invalid public key", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  "EcdsaSecp256k1VerificationKey2019",
			Value: []byte("invalid public key"),
			JWK: &jose.JWK{
				JSONWebKey: gojose.JSONWebKey{
					Algorithm: "ES256K",
				},
				Crv: "secp256k1",
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

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...)
}
