/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/crypto"
)

func TestToECKey(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{
			name:  "to P-256 key",
			curve: elliptic.P256(),
		},
		{
			name:  "to P-384 key",
			curve: elliptic.P384(),
		},
		{
			name:  "to P-521 key",
			curve: elliptic.P521(),
		},
		{
			name:  "invalid curve",
			curve: nil,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "invalid curve" {
				_, err := ToECKey(&crypto.PublicKey{
					Curve: "undefined",
					Type:  "EC",
				})
				require.EqualError(t, err, "invalid curve 'undefined'")

				return
			}

			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			pubKey := &crypto.PublicKey{
				X:     privKey.X.Bytes(),
				Y:     privKey.Y.Bytes(),
				Curve: tc.curve.Params().Name,
				Type:  "EC",
			}

			pubECKey, err := ToECKey(pubKey)
			require.NoError(t, err)
			require.Equal(t, tc.curve.Params().Name, pubECKey.Curve.Params().Name)
			require.EqualValues(t, privKey.X.Bytes(), pubECKey.X.Bytes())
			require.EqualValues(t, privKey.Y.Bytes(), pubECKey.Y.Bytes())
		})
	}
}
