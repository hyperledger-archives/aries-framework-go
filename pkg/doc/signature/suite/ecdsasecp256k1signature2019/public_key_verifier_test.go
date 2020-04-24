/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsasecp256k1signature2019

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	btcecPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	ecdsaPrivKey := btcecPrivKey.ToECDSA()

	msg := []byte("test message")

	btcecPubKey := btcecPrivKey.PubKey()

	pubKey := &verifier.PublicKey{
		Type: "EcdsaSecp256k1VerificationKey2019",

		JWK: &jose.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Algorithm: "ES256K",
				Key:       btcecPubKey.ToECDSA(),
			},
			Crv: "secp256k1",
			Kty: "EC",
		},
	}

	v := NewPublicKeyVerifier()
	signature, err := getSignature(ecdsaPrivKey, msg)
	require.NoError(t, err)

	err = v.Verify(pubKey, msg, signature)
	require.NoError(t, err)

	pubKeyBytes := elliptic.Marshal(btcecPubKey.Curve, btcecPubKey.X, btcecPubKey.Y)
	pubKey = &verifier.PublicKey{
		Type:  "EcdsaSecp256k1VerificationKey2019",
		Value: pubKeyBytes,
	}

	err = v.Verify(pubKey, msg, signature)
	require.NoError(t, err)
}

func getSignature(privKey *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		return nil, err
	}

	// use DER format of signature
	ecdsaSig := verifier.NewECDSASignature(r, s)

	ret, err := asn1.Marshal(*ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("asn.1 encoding failed: %w", err)
	}

	return ret, nil
}
