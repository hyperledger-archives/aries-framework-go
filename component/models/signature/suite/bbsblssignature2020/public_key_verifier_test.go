/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignature2020

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	sigverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

//nolint:lll
func TestNewG2PublicKeyVerifier(t *testing.T) {
	verifier := NewG2PublicKeyVerifier()

	pkBase64 := "lOpN7uGZWivVIjs0325N/V0dAhoPomrgfXVpg7pZNdRWwFwJDVxoE7TvRyOx/Qr7GMtShNuS2Px/oScD+SMf08t8eAO78QRNErPzwNpfkP4ppcSTShStFDfFbsv9L9yb"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := "hPbLkeMZZ6KKzkjWoTVHeMeuLJfYWjmdAU1Vg5fZ/VZnIXxxeXBB+q0/EL8XQmWkOMMwEGA/D2dCb4MDuntKZpvHEHlvaFR6l1A4bYj0t2Jd6bYwGwCwirNbmSeIoEmJeRzJ1cSvsL+jxvLixdDPnw=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	msg := `
message1
message2
`

	err = verifier.Verify(&sigverifier.PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pkBytes,
	}, []byte(msg), sigBytes)
	require.NoError(t, err)

	err = verifier.Verify(&sigverifier.PublicKey{
		Type:  "NotBls12381G2Key2020",
		Value: pkBytes,
	}, []byte(msg), sigBytes)
	require.Error(t, err)
	require.EqualError(t, err, "a type of public key is not 'Bls12381G2Key2020'")

	// Success as we now support JWK for Bls12381G2Key2020.
	err = verifier.Verify(&sigverifier.PublicKey{
		Type: "Bls12381G2Key2020",
		JWK: &jwk.JWK{
			Kty: "EC",
			Crv: "BLS12381_G2",
		},
		Value: pkBytes,
	}, []byte(msg), sigBytes)
	require.NoError(t, err)
}
