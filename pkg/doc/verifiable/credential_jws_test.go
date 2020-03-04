/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTCredClaimsMarshalJWS(t *testing.T) {
	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	require.NoError(t, err)

	vc, _, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWS(RS256, getRS256TestSigner(privateKey), "any")
		require.NoError(t, err)

		vcBytes, err := decodeCredJWS(jws, true, func(issuerID, keyID string) (i interface{}, e error) {
			publicKey, pcErr := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
			require.NoError(t, pcErr)
			require.NotNil(t, publicKey)

			return publicKey, nil
		})
		require.NoError(t, err)

		vcRaw := new(rawCredential)
		err = json.Unmarshal(vcBytes, &vcRaw)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), vcRaw.stringJSON(t))
	})
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestCredJWSDecoderUnmarshal(t *testing.T) {
	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	require.NoError(t, err)

	pkFetcher := func(_, _ string) (interface{}, error) {
		publicKey, err := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
		require.NoError(t, err)
		require.NotNil(t, publicKey)

		return publicKey, err
	}

	validJWS := createRS256JWS(t, []byte(jwtTestCredential), false)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		vcBytes, err := decodeCredJWS(string(validJWS), true, pkFetcher)
		require.NoError(t, err)

		vcRaw := new(rawCredential)
		err = json.Unmarshal(vcBytes, &vcRaw)
		require.NoError(t, err)

		vc, _, err := NewCredential([]byte(jwtTestCredential))
		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), vcRaw.stringJSON(t))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		jws, err := decodeCredJWS("invalid JWS", true, pkFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		key := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		jwtCompact, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		jws, err := decodeCredJWS(jwtCompact, true, pkFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		pkFetcherOther := func(issuerID, keyID string) (interface{}, error) {
			// use public key of VC Holder (while expecting to use the ones of Issuer)
			publicKey, err := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
			require.NoError(t, err)
			require.NotNil(t, publicKey)

			return publicKey, nil
		}

		jws, err := decodeCredJWS(string(validJWS), true, pkFetcherOther)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
	})
}
