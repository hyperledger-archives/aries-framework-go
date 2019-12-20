/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"path/filepath"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTPresClaims_MarshalJWS(t *testing.T) {
	vp, err := NewPresentation([]byte(validPresentation))
	require.NoError(t, err)

	jws := createCredJWS(t, vp)

	_, rawVC, err := decodeVPFromJWS([]byte(jws), true, holderPublicKeyFetcher(t))

	require.NoError(t, err)
	require.Equal(t, vp.raw().stringJSON(t), rawVC.stringJSON(t))
}

type invalidPresClaims struct {
	*jwt.Claims

	Presentation int `json:"vp,omitempty"`
}

func TestUnmarshalPresJWSClaims(t *testing.T) {
	testFetcher := holderPublicKeyFetcher(t)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		jws := createCredJWS(t, vp)

		claims, err := unmarshalPresJWSClaims([]byte(jws), true, testFetcher)
		require.NoError(t, err)
		require.Equal(t, vp.raw().stringJSON(t), claims.Presentation.stringJSON(t))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		claims, err := unmarshalPresJWSClaims([]byte("invalid JWS"), true, testFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "VP is not valid serialized JWS")
		require.Nil(t, claims)
	})

	t.Run("Invalid format of \"vp\" claim", func(t *testing.T) {
		privateKey, err := readPrivateKey(filepath.Join(certPrefix, "holder_private.pem"))
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidPresClaims{
			Claims:       &jwt.Claims{},
			Presentation: 55, // "vp" claim of invalid format
		}

		token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		uc, err := unmarshalPresJWSClaims([]byte(token), true, testFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT claims")
		require.Nil(t, uc)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		vp, err := NewPresentation([]byte(validPresentation))
		require.NoError(t, err)

		jws := createCredJWS(t, vp)

		uc, err := unmarshalPresJWSClaims([]byte(jws), true, func(issuerID, keyID string) (interface{}, error) {
			// use public key of VC Issuer (while expecting to use the ones of VP Holder)
			publicKey, pkErr := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
			require.NoError(t, pkErr)
			require.NotNil(t, publicKey)

			return publicKey, nil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWT signature verification: verify JWT signature")
		require.Nil(t, uc)
	})
}

func createCredJWS(t *testing.T, vp *Presentation) string {
	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "holder_private.pem"))
	require.NoError(t, err)

	claims := newJWTPresClaims(vp, []string{}, false)
	require.NotNil(t, claims)

	jws, err := claims.MarshalJWS(RS256, privateKey, "any")
	require.NoError(t, err)

	return jws
}

func holderPublicKeyFetcher(t *testing.T) PublicKeyFetcher {
	return func(issuerID, keyID string) (i interface{}, e error) {
		publicKey, pcErr := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
		require.NoError(t, pcErr)
		require.NotNil(t, publicKey)

		return publicKey, nil
	}
}
