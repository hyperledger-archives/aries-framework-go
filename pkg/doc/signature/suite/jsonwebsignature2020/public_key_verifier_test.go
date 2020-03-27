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

	"github.com/stretchr/testify/require"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")

	pubKeyBytes := elliptic.Marshal(curve, privKey.X, privKey.Y)
	pubKey := &sigverifier.PublicKey{
		Type:  kms.ED25519,
		Value: pubKeyBytes,
	}

	v := &PublicKeyVerifierP256{}
	signature := getSignature(privKey, msg)

	t.Run("happy path", func(t *testing.T) {
		verifyError := v.Verify(pubKey, msg, signature)
		require.NoError(t, verifyError)
	})

	t.Run("invalid public key", func(t *testing.T) {
		verifyError := v.Verify(&sigverifier.PublicKey{
			Type:  kms.ED25519,
			Value: []byte("invalid public key"),
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

	// According to documentation, Write() on hash never fails
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

	// We serialize the outputs (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return out
}
