/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/elliptic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestMapECCurveToKeyType(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		keyType kms.KeyType
	}{
		{
			name:    "P256",
			curve:   elliptic.P256(),
			keyType: kms.ECDSAP256TypeIEEEP1363,
		},
		{
			name:    "P384",
			curve:   elliptic.P384(),
			keyType: kms.ECDSAP384TypeIEEEP1363,
		},
		{
			name:    "P521",
			curve:   elliptic.P521(),
			keyType: kms.ECDSAP521TypeIEEEP1363,
		},
		{
			name:    "secp256k1",
			curve:   btcec.S256(),
			keyType: kms.ECDSASecp256k1TypeIEEEP1363,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			keyType, err := MapECCurveToKeyType(tt.curve)
			require.NoError(t, err)
			require.Equal(t, tt.keyType, keyType)
		})
	}

	_, err := MapECCurveToKeyType(elliptic.P224())
	require.Error(t, err)
	require.EqualError(t, err, "unsupported curve")
}
