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

func TestCredentialJWTClaimsMarshallingToUnsecuredJWT(t *testing.T) {
	vc, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	sJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)
	require.NotNil(t, sJWT)

	_, rawVC, err := decodeCredJWTUnsecured([]byte(sJWT))

	require.NoError(t, err)
	require.Equal(t, vc.raw().stringJSON(t), rawVC.stringJSON(t))
}

func TestCredUnsecuredJWTDecoderParseJWTClaims(t *testing.T) {
	t.Run("Successful unsecured JWT decoding", func(t *testing.T) {
		vc, err := NewCredential([]byte(validCredential))
		require.NoError(t, err)

		jwtClaims, err := vc.JWTClaims(true)
		require.NoError(t, err)

		sJWT, err := jwtClaims.MarshalUnsecuredJWT()
		require.NoError(t, err)

		decoder := &credUnsecuredJWTDecoder{}

		decodedCred, err := decoder.UnmarshalClaims([]byte(sJWT))
		require.NoError(t, err)
		require.NotNil(t, decodedCred)
	})

	t.Run("Invalid serialized unsecured JWT", func(t *testing.T) {
		decoder := new(credUnsecuredJWTDecoder)

		_, err := decoder.UnmarshalClaims([]byte("invalid JWS"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode unsecured JWT")

		_, err = decoder.UnmarshalVCClaim([]byte("invalid JWS"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode unsecured JWT")
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		rawJWT, err := marshalUnsecuredJWT(map[string]string{}, claims)
		require.NoError(t, err)

		decoder := new(credUnsecuredJWTDecoder)

		_, err = decoder.UnmarshalClaims([]byte(rawJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse JWT claims")

		_, err = decoder.UnmarshalVCClaim([]byte(rawJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse JWT claims")
	})
}
