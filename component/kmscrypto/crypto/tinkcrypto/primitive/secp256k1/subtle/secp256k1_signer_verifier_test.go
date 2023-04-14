/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	subtleSignature "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

func TestSignVerify(t *testing.T) {
	data := random.GetRandomBytes(20)
	hash := "SHA256"
	curve := "SECP256K1"
	encodings := []string{"Bitcoin_DER", "Bitcoin_IEEE_P1363"}

	for _, encoding := range encodings {
		priv, err := ecdsa.GenerateKey(subtleSignature.GetCurve(curve), rand.Reader)
		require.NoError(t, err)

		// Use the private key and public key directly to create new instances
		signer, err := subtleSignature.NewSecp256K1SignerFromPrivateKey(hash, encoding, priv)
		require.NoError(t, err, "unexpected error when creating Secp256K1Signer")

		verifier, err := subtleSignature.NewSecp256K1VerifierFromPublicKey(hash, encoding, &priv.PublicKey)
		require.NoError(t, err, "unexpected error when creating ECDSAVerifier")

		signature, err := signer.Sign(data)
		require.NoError(t, err, "unexpected error when signing")

		err = verifier.Verify(signature, data)
		require.NoError(t, err, "unexpected error when verifying")

		// Use byte slices to create new instances
		signer, err = subtleSignature.NewSecp256K1Signer(hash, curve, encoding, priv.D.Bytes())
		require.NoError(t, err, "unexpected error when creating Secp256K1Signer")

		verifier, err = subtleSignature.NewSecp256K1Verifier(hash, curve, encoding, priv.X.Bytes(), priv.Y.Bytes())
		require.NoError(t, err, "unexpected error when creating ECDSAVerifier")

		signature, err = signer.Sign(data)
		require.NoError(t, err, "unexpected error when signing")

		err = verifier.Verify(signature, data)
		require.NoError(t, err, "unexpected error when verifying")
	}
}
