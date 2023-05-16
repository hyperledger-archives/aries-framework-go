/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestJWTPresClaims_MarshalJWS(t *testing.T) {
	vp, err := newTestPresentation(t, []byte(validPresentation))
	require.NoError(t, err)

	signer, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	jws := createCredJWS(t, vp, signer)

	_, rawVC, err := decodeVPFromJWS(jws, true, holderPublicKeyFetcher(signer.PublicKeyBytes()))

	require.NoError(t, err)
	require.Equal(t, vp.stringJSON(t), rawVC.stringJSON(t))
}

type invalidPresClaims struct {
	*jwt.Claims

	Presentation int `json:"vp,omitempty"`
}

func TestUnmarshalPresJWSClaims(t *testing.T) {
	holderSigner, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	testFetcher := holderPublicKeyFetcher(holderSigner.PublicKeyBytes())

	t.Run("Successful JWS decoding", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation))
		require.NoError(t, err)

		jws := createCredJWS(t, vp, holderSigner)

		claims, err := unmarshalPresJWSClaims(jws, true, testFetcher)
		require.NoError(t, err)
		require.Equal(t, vp.stringJSON(t), claims.Presentation.stringJSON(t))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		claims, err := unmarshalPresJWSClaims("invalid JWS", true, testFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT")
		require.Nil(t, claims)
	})

	t.Run("Invalid format of \"vp\" claim", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidPresClaims{
			Claims:       &jwt.Claims{},
			Presentation: 55, // "vp" claim of invalid format
		}

		token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		uc, err := unmarshalPresJWSClaims(token, true, testFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT")
		require.Nil(t, uc)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		vp, err := newTestPresentation(t, []byte(validPresentation))
		require.NoError(t, err)

		jws := createCredJWS(t, vp, holderSigner)

		uc, err := unmarshalPresJWSClaims(jws, true, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			// use public key of VC Issuer (while expecting to use the ones of VP Holder)
			issuerSigner, errSigner := newCryptoSigner(kms.RSARS256Type)
			require.NoError(t, errSigner)

			return &verifier.PublicKey{
				Type:  kms.RSARS256,
				Value: issuerSigner.PublicKeyBytes(),
			}, nil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse JWT")
		require.Nil(t, uc)
	})
}

func createCredJWS(t *testing.T, vp *Presentation, signer Signer) string {
	claims, err := newJWTPresClaims(vp, []string{}, false)
	require.NoError(t, err)
	require.NotNil(t, claims)

	jws, err := claims.MarshalJWS(RS256, signer, "did:123#key1")
	require.NoError(t, err)

	return jws
}

func holderPublicKeyFetcher(pubKeyBytes []byte) PublicKeyFetcher {
	return func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return &verifier.PublicKey{
			Type:  kms.RSARS256,
			Value: pubKeyBytes,
		}, nil
	}
}
