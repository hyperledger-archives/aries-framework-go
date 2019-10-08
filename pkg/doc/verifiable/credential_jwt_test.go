/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestCredentialJWTClaimsMarshallingToJWS(t *testing.T) {
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

	t.Run("Marshal plain (unsecured) JWT", func(t *testing.T) {
		sJWT, err := jwtClaims.MarshalUnsecuredJWT()
		require.NoError(t, err)
		require.NotNil(t, sJWT)

		_, rawVC, err := decodeCredJWTUnsecured([]byte(sJWT))

		require.NoError(t, err)
		require.Equal(t, vc.raw().stringJSON(t), rawVC.stringJSON(t))
	})
}

type badParseJWTClaims struct{}

func (b badParseJWTClaims) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	return nil, errors.New("cannot parse JWT claims")
}

func (b badParseJWTClaims) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	return new(jwtVCClaim).VC, nil
}

type badParseJWTRawClaims struct{}

func (b badParseJWTRawClaims) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	return new(JWTCredClaims), nil
}

func (b badParseJWTRawClaims) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	return nil, errors.New("cannot parse raw JWT claims")
}

func TestDecodeJWT(t *testing.T) {
	_, _, err := decodeCredJWT([]byte{}, &badParseJWTClaims{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse JWT claims")

	_, _, err = decodeCredJWT([]byte{}, &badParseJWTRawClaims{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse raw JWT claims")
}

type invalidCredClaims struct {
	*jwt.Claims

	Credential int `json:"vc,omitempty"`
}

func TestCredJWSDecoderParseJWTClaims(t *testing.T) {
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
