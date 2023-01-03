/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
)

const (
	testIssuer = "https://example.com/issuer"
)

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, claims, nil, signer)
	r.NoError(e)
	sdJWTSerialized, e := token.Serialize(false)
	r.NoError(e)

	verifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.NoError(err)
		require.NotNil(t, sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))
	})

	t.Run("success - RS256 signing algorithm", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		v := afjwt.NewRS256Verifier(pubKey)

		token, err := issuer.New(testIssuer, claims, nil, afjwt.NewRS256Signer(privKey, nil))
		r.NoError(err)
		tokenSerialized, err := token.Serialize(false)
		require.NoError(t, err)

		sdJWT, err := Parse(tokenSerialized, WithSignatureVerifier(v))
		r.NoError(err)
		require.NotNil(t, sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))
	})

	t.Run("success - valid SD-JWT times", func(t *testing.T) {
		now := time.Now()
		oneHourInThePast := now.Add(-time.Hour)
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, claims, nil, signer,
			issuer.WithIssuedAt(jwt.NewNumericDate(oneHourInThePast)),
			issuer.WithNotBefore(jwt.NewNumericDate(oneHourInThePast)),
			issuer.WithExpiry(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		serialized, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		sdJWT, err := Parse(serialized, WithSignatureVerifier(verifier))
		r.NoError(err)
		r.NotNil(sdJWT)
	})

	t.Run("error - signing algorithm not supported", func(t *testing.T) {
		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier), WithSigningAlgorithms([]string{}))
		r.Error(err)
		require.Nil(t, sdJWT)
		require.Equal(t, err.Error(), "alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - additional disclosure", func(t *testing.T) {
		sdJWT, err := Parse(fmt.Sprintf("%s~%s", sdJWTSerialized, additionalDisclosure), WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(sdJWT)
		r.Contains(err.Error(),
			"disclosure digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' not found in SD-JWT disclosure digests")
	})

	t.Run("error - duplicate disclosure", func(t *testing.T) {
		sdJWT, err := Parse(fmt.Sprintf("%s~%s~%s", sdJWTSerialized, additionalDisclosure, additionalDisclosure),
			WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(sdJWT)
		r.Contains(err.Error(),
			"check disclosures: duplicate values found [WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd]")
	})

	t.Run("success - with detached payload", func(t *testing.T) {
		jwsParts := strings.Split(sdJWTSerialized, ".")
		jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

		jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
		require.NoError(t, err)

		sdJWT, err := Parse(jwsDetached,
			WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
		r.NoError(err)
		r.NotNil(r, sdJWT)
	})

	t.Run("error - invalid claims format", func(t *testing.T) {
		// claims is not JSON
		sdJWTSerialized, err := buildJWS(signer, "not JSON")
		r.NoError(err)

		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "read JWT claims from JWS payload")
		r.Nil(sdJWT)
	})

	t.Run("error - invalid claims(iat)", func(t *testing.T) {
		now := time.Now()
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, claims, nil, signer,
			issuer.WithIssuedAt(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		sdJWTSerialized, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"failed to validate SD-JWT time values: go-jose/go-jose/jwt: validation field, token issued in the future (iat)")
		r.Nil(sdJWT)
	})

	t.Run("error - invalid claims(nbf)", func(t *testing.T) {
		now := time.Now()
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, claims, nil, signer,
			issuer.WithNotBefore(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		sdJWTSerialized, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"failed to validate SD-JWT time values: go-jose/go-jose/jwt: validation failed, token not valid yet (nbf)")
		r.Nil(sdJWT)
	})

	t.Run("error - invalid claims(expiry)", func(t *testing.T) {
		now := time.Now()
		oneHourInThePast := now.Add(-time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, claims, nil, signer,
			issuer.WithExpiry(jwt.NewNumericDate(oneHourInThePast)))
		r.NoError(e)
		sdJWTSerialized, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"failed to validate SD-JWT time values: go-jose/go-jose/jwt: validation failed, token is expired (exp)")
		r.Nil(sdJWT)
	})
}

func TestVerifySigningAlgorithm(t *testing.T) {
	r := require.New(t)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		headers := make(jose.Headers)
		headers["alg"] = "EdDSA"
		err := verifySigningAlg(headers, []string{"EdDSA"})
		r.NoError(err)
	})

	t.Run("error - signing algorithm can not be empty", func(t *testing.T) {
		headers := make(jose.Headers)
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "missing alg")
	})

	t.Run("success - EdDSA signing algorithm not in allowed list", func(t *testing.T) {
		headers := make(jose.Headers)
		headers["alg"] = "EdDSA"
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - signing algorithm can not be none", func(t *testing.T) {
		headers := make(jose.Headers)
		headers["alg"] = "none"
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg value cannot be 'none'")
	})
}

func TestWithJWTDetachedPayload(t *testing.T) {
	detachedPayloadOpt := WithJWTDetachedPayload([]byte("payload"))
	require.NotNil(t, detachedPayloadOpt)

	opts := &parseOpts{}
	detachedPayloadOpt(opts)
	require.Equal(t, []byte("payload"), opts.detachedPayload)
}

func buildJWS(signer jose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

const additionalDisclosure = `WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`
