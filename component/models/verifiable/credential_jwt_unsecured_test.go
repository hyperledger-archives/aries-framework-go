/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

func TestCredentialJWTClaimsMarshallingToUnsecuredJWT(t *testing.T) {
	vc, err := parseTestCredential(t, []byte(validCredential))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	sJWT, err := jwtClaims.MarshalUnsecuredJWT()
	require.NoError(t, err)
	require.NotNil(t, sJWT)

	vcBytes, err := decodeCredJWTUnsecured(sJWT)
	require.NoError(t, err)

	vcRaw := new(rawCredential)
	err = json.Unmarshal(vcBytes, &vcRaw)
	require.NoError(t, err)

	require.NoError(t, err)
	require.Equal(t, vc.stringJSON(t), vcRaw.stringJSON(t))
}

func TestCredUnsecuredJWTDecoderParseJWTClaims(t *testing.T) {
	t.Run("Successful unsecured JWT decoding", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential))
		require.NoError(t, err)

		jwtClaims, err := vc.JWTClaims(true)
		require.NoError(t, err)

		sJWT, err := jwtClaims.MarshalUnsecuredJWT()
		require.NoError(t, err)

		decodedCred, err := decodeCredJWTUnsecured(sJWT)
		require.NoError(t, err)
		require.NotNil(t, decodedCred)
	})

	t.Run("Invalid serialized unsecured JWT", func(t *testing.T) {
		vcBytes, err := decodeCredJWTUnsecured("invalid JWS")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse VC in JWT Unsecured form")
		require.Nil(t, vcBytes)
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		rawJWT, err := marshalUnsecuredJWT(jose.Headers{}, claims)
		require.NoError(t, err)

		vcBytes, err := decodeCredJWTUnsecured(rawJWT)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, vcBytes)
	})
}
