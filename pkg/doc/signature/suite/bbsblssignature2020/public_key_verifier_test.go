/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignature2020

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

//nolint:lll
func TestNewG2PublicKeyVerifier(t *testing.T) {
	verifier := NewG2PublicKeyVerifier()

	pkBase64 := "iQp7qpSrUoYYvtYylMp61k/8/U8JgiFp+sp6AIppkByvsZ4fpbMjWqePcGkXNuKJE+pE2VqTSOs0meYy3JNj12ksKVoP0DF4ZaFgg+Q+8Gw/npZy50TcWvOBPGyHnxRC"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := "gcwMuYBElR0ESVFWQqerR7Vfb4+6nJ1zF8iM4BPQ+PmSF2kXPkRSaUtkEgpS1KuFLAMwV4L/18Pu1BMWd0YBzY4MssdCwsQYerREXQNzoDJlQf0IEf91Ucdzn6MJecpEbaYvHJC8ciddUUEuVVQlVg=="
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
