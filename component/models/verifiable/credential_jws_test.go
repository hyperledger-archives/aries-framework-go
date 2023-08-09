/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	ariesjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

func TestJWTCredClaimsMarshalJWS(t *testing.T) {
	signer, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	vc, err := parseTestCredential(t, []byte(validCredential))
	require.NoError(t, err)

	jwtClaims, err := vc.JWTClaims(true)
	require.NoError(t, err)

	t.Run("Marshal signed JWT", func(t *testing.T) {
		jws, err := jwtClaims.MarshalJWS(RS256, signer, "did:123#key1")
		require.NoError(t, err)

		headers, vcBytes, err := decodeCredJWS(jws, true, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{
				Type:  kms.RSARS256,
				Value: signer.PublicKeyBytes(),
			}, nil
		})
		require.NoError(t, err)
		require.Equal(t, ariesjose.Headers{"alg": "RS256", "kid": "did:123#key1"}, headers)

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
	signer, err := newCryptoSigner(kms.RSARS256Type)
	require.NoError(t, err)

	pkFetcher := func(_, _ string) (*verifier.PublicKey, error) { //nolint:unparam
		return &verifier.PublicKey{
			Type:  kms.RSARS256,
			Value: signer.PublicKeyBytes(),
		}, nil
	}

	validJWS := createRS256JWS(t, []byte(jwtTestCredential), signer, false)

	t.Run("Successful JWS decoding", func(t *testing.T) {
		headers, vcBytes, err := decodeCredJWS(string(validJWS), true, pkFetcher)
		require.NoError(t, err)
		require.NotNil(t, headers)

		vcRaw := new(rawCredential)
		err = json.Unmarshal(vcBytes, &vcRaw)
		require.NoError(t, err)

		vc, err := parseTestCredential(t, []byte(jwtTestCredential))
		require.NoError(t, err)
		require.Equal(t, vc.stringJSON(t), vcRaw.stringJSON(t))
	})

	t.Run("Invalid serialized JWS", func(t *testing.T) {
		joseHeaders, jws, err := decodeCredJWS("invalid JWS", true, pkFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})

	t.Run("Invalid format of \"vc\" claim", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		key := jose.SigningKey{Algorithm: jose.RS256, Key: privKey}

		signer, err := jose.NewSigner(key, &jose.SignerOptions{})
		require.NoError(t, err)

		claims := &invalidCredClaims{
			Claims:     &jwt.Claims{},
			Credential: 55, // "vc" claim of invalid format
		}

		jwtCompact, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		joseHeaders, jws, err := decodeCredJWS(jwtCompact, true, pkFetcher)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})

	t.Run("Invalid signature of JWS", func(t *testing.T) {
		pkFetcherOther := func(issuerID, keyID string) (*verifier.PublicKey, error) {
			// use public key of VC Holder (while expecting to use the ones of Issuer)
			holderSigner, err := newCryptoSigner(kms.RSARS256Type)
			require.NoError(t, err)

			return &verifier.PublicKey{
				Type:  kms.RSARS256,
				Value: holderSigner.PublicKeyBytes(),
			}, nil
		}

		joseHeaders, jws, err := decodeCredJWS(string(validJWS), true, pkFetcherOther)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		require.Nil(t, jws)
		require.Nil(t, joseHeaders)
	})
}
