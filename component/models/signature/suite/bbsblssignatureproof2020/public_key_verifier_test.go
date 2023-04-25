/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignatureproof2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

//nolint:lll
func TestNewG2PublicKeyVerifier(t *testing.T) {
	publicKeyVerifier := bbsblssignatureproof2020.NewG2PublicKeyVerifier([]byte("nonce"))

	pkBase64 := "sVEbbh9jDPGSBK/oT/EeXQwFvNuC+47rgq9cxXKrwo6G7k4JOY/vEcfgZw9Vf/TpArbIdIAJCFMDyTd7l2atS5zExAKX0B/9Z3E/mgIZeQJ81iZ/1HUnUCT2Om239KFx"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := "AAIBiN4EL9psRsIUlwQah7a5VROD369PPt09Z+jfzamP+/114a5RfWVMju3NCUl2Yv6ahyIdHGdEfxhC985ShlGQrRPLa+crFRiu2pfnAk+L6QMNooVMQhzJc2yYgktHen4QhsKV3IGoRRUs42zqPTP3BdqIPQeLgjDVi1d1LXEnP+WFQGEQmTKWTja4u1MsERdmAAAAdIb6HuFznhE3OByXN0Xp3E4hWQlocCdpExyNlSLh3LxK5duCI/WMM7ETTNS0Ozxe3gAAAAIuALkiwplgKW6YmvrEcllWSkG3H+uHEZzZGL6wq6Ac0SuktQ4n84tZPtMtR9vC1Rsu8f7Kwtbq1Kv4v02ct9cvj7LGcitzg3u/ZO516qLz+iitKeGeJhtFB8ggALcJOEsebPFl12cYwkieBbIHCBt4AAAAAxgEHt3iqKIyIQbTYJvtrMjGjT4zuimiZbtE3VXnqFmGaxVTeR7dh89PbPtsBI8LLMrCvFFpks9D/oTzxnw13RBmMgMlc1bcfQOmE9DZBGB7NCdwOnT7q4TVKhswOITKTQ=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	msg := `
message1
message2
`

	err = publicKeyVerifier.Verify(&verifier.PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pkBytes,
	}, []byte(msg), sigBytes)
	require.NoError(t, err)

	err = publicKeyVerifier.Verify(&verifier.PublicKey{
		Type:  "NotBls12381G2Key2020",
		Value: pkBytes,
	}, []byte(msg), sigBytes)
	require.Error(t, err)
	require.EqualError(t, err, "a type of public key is not 'Bls12381G2Key2020'")

	// Failed as we do not support JWK for Bls12381G2Key2020.
	err = publicKeyVerifier.Verify(&verifier.PublicKey{
		Type: "Bls12381G2Key2020",
		JWK: &jwk.JWK{
			Kty: "EC",
			Crv: "BLS12381_G2",
		},
	}, []byte(msg), sigBytes)
	require.Error(t, err)
	require.EqualError(t, err, "verifier does not match JSON Web Key")
}
