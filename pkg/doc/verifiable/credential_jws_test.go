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

func TestJWTCredClaimsMarshalJWS(t *testing.T) {
	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	require.NoError(t, err)

	vc, err := NewCredential([]byte(validCredential))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWS(RS256, privateKey, "any")
		require.NoError(t, err)

		_, rawVC, err := decodeCredJWS([]byte(jws), func(issuerID, keyID string) (i interface{}, e error) {
			publicKey, pcErr := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
			require.NoError(t, pcErr)
			require.NotNil(t, publicKey)

			return publicKey, nil
		})

		require.NoError(t, err)
		require.Equal(t, vc.raw().stringJSON(t), rawVC.stringJSON(t))
	})

	t.Run("Marshal signed JWT failed with invalid private key", func(t *testing.T) {
		_, err := jwtClaims.MarshalJWS(RS256, "invalid private key", "any")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create signer")
	})
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestCredJWSDecoderUnmarshal(t *testing.T) {
	privateKey, err := readPrivateKey(filepath.Join(certPrefix, "issuer_private.pem"))
	require.NoError(t, err)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		jws := createJWS(t, []byte(jwtTestCredential), false)

		decoder := &credJWSDecoder{
			PKFetcher: func(issuerID, keyID string) (i interface{}, e error) {
				publicKey, err := readPublicKey(filepath.Join(certPrefix, "issuer_public.pem"))
				require.NoError(t, err)
				require.NotNil(t, publicKey)

				return publicKey, nil
			},
		}

		decodedCred, err := decoder.UnmarshalClaims(jws)
		require.NoError(t, err)

		vc, err := NewCredential([]byte(jwtTestCredential))
		require.NoError(t, err)
		require.Equal(t, vc.raw().stringJSON(t), decodedCred.Credential.stringJSON(t))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		decoder := new(credJWSDecoder)

		_, err := decoder.UnmarshalClaims([]byte("invalid JWS"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "VC is not valid serialized JWS")

		_, err = decoder.UnmarshalVCClaim([]byte("invalid JWS"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "VC is not valid serialized JWS")
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		key := jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		rawJWT, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		decoder := new(credJWSDecoder)

		_, err = decoder.UnmarshalClaims([]byte(rawJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse JWT claims")

		_, err = decoder.UnmarshalVCClaim([]byte(rawJWT))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse JWT claims")
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		jws := createJWS(t, []byte(jwtTestCredential), false)

		decoder := &credJWSDecoder{
			PKFetcher: func(issuerID, keyID string) (i interface{}, e error) {
				// use public key of VC Holder (while expecting to use the ones of Issuer)
				publicKey, err := readPublicKey(filepath.Join(certPrefix, "holder_public.pem"))
				require.NoError(t, err)
				require.NotNil(t, publicKey)

				return publicKey, nil
			},
		}

		_, err := decoder.UnmarshalClaims(jws)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWT signature verification failed")
	})
}
