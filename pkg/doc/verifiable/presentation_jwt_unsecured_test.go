/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTPresClaims_MarshalUnsecuredJWT(t *testing.T) {
	vp, err := NewPresentation([]byte(validPresentation))
	require.NoError(t, err)

	jws := createCredUnsecuredJWT(t, vp)

	_, rawVC, err := decodeVPFromUnsecuredJWT([]byte(jws))

	require.NoError(t, err)
	require.Equal(t, vp.raw().stringJSON(t), rawVC.stringJSON(t))
}

func TestDecodeVPFromUnsecuredJWT(t *testing.T) {
	t.Run("Successful unsecured JWT decoding", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		jws := createCredUnsecuredJWT(t, vp)

		vpDecodedBytes, vpRaw, err := decodeVPFromUnsecuredJWT([]byte(jws))
		require.NoError(t, err)
		require.NotNil(t, vpDecodedBytes)
		require.Equal(t, vp.raw().stringJSON(t), vpRaw.stringJSON(t))
	})

	t.Run("Invalid serialized unsecured JWT", func(t *testing.T) {
		vpBytes, vpRaw, err := decodeVPFromUnsecuredJWT([]byte("invalid JWS"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode Verifiable Presentation JWT claims")
		require.Nil(t, vpBytes)
		require.Nil(t, vpRaw)
	})

	t.Run("Invalid format of \"vp\" claim", func(t *testing.T) {
		claims := &invalidPresClaims{
			Claims:       &jwt.Claims{},
			Presentation: 55, // "vp" claim of invalid format
		}

		rawJWT, err := marshalUnsecuredJWT(map[string]string{}, claims)
		require.NoError(t, err)

		vpBytes, vpRaw, err := decodeVPFromUnsecuredJWT([]byte(rawJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode Verifiable Presentation JWT claims: parse JWT claims")
		require.Nil(t, vpBytes)
		require.Nil(t, vpRaw)
	})
}

func createCredUnsecuredJWT(t *testing.T, vp *Presentation) string {
	claims := newJWTPresClaims(vp, []string{}, false)
	require.NotNil(t, claims)

	unsecuredJWT, err := claims.MarshalUnsecuredJWT()
	require.NoError(t, err)

	return unsecuredJWT
}
