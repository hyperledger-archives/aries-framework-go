/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmssigner

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mockcrypto "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestKMSSigner_Alg(t *testing.T) {
	tests := []struct {
		name        string
		kmsKT       kmsapi.KeyType
		expectedAlg string
	}{
		{
			name:        "test ECDSA alg from P256 key type in DER format",
			kmsKT:       kmsapi.ECDSAP256DER,
			expectedAlg: p256Alg,
		},
		{
			name:        "test ECDSA alg from P256 key type in IEEE format",
			kmsKT:       kmsapi.ECDSAP256IEEEP1363,
			expectedAlg: p256Alg,
		},
		{
			name:        "test ECDSA alg from P384 key type in DER format",
			kmsKT:       kmsapi.ECDSAP384DER,
			expectedAlg: p384Alg,
		},
		{
			name:        "test ECDSA alg from P384 key type in IEEE format",
			kmsKT:       kmsapi.ECDSAP384IEEEP1363,
			expectedAlg: p384Alg,
		},
		{
			name:        "test ECDSA alg from P521 key type in DER format",
			kmsKT:       kmsapi.ECDSAP521DER,
			expectedAlg: p521Alg,
		},
		{
			name:        "test ECDSA alg from P521 key type in IEEE format",
			kmsKT:       kmsapi.ECDSAP521IEEEP1363,
			expectedAlg: p521Alg,
		},
		{
			name:        "test EdDSA alg from ed25519 key type",
			kmsKT:       kmsapi.ED25519,
			expectedAlg: edAlg,
		},
		{
			name: "test empty alg from empty key type",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			signer := KMSSigner{
				KeyType: tc.kmsKT,
			}

			alg := signer.Alg()
			require.Equal(t, tc.expectedAlg, alg)
		})
	}
}

func TestKMSSigner_Sign(t *testing.T) {
	signError := errors.New("sign error")
	signResult := []byte("abc")

	t.Run("sign success", func(t *testing.T) {
		signer := KMSSigner{Crypto: &mockcrypto.Crypto{SignValue: signResult}}

		res, err := signer.Sign([]byte("1234"))
		require.NoError(t, err)
		require.Equal(t, signResult, res)
	})

	t.Run("Multi-message sign success", func(t *testing.T) {
		signer := KMSSigner{
			Crypto:   &mockcrypto.Crypto{BBSSignValue: signResult},
			MultiMsg: true,
		}

		res, err := signer.Sign([]byte("1234\n4321\nabcd"))
		require.NoError(t, err)
		require.Equal(t, signResult, res)
	})

	t.Run("sign error", func(t *testing.T) {
		signer := KMSSigner{Crypto: &mockcrypto.Crypto{SignErr: signError}}

		res, err := signer.Sign([]byte("1234"))
		require.Error(t, err)
		require.ErrorIs(t, err, signError)
		require.Empty(t, res)
	})
}
