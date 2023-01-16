/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

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

	afjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
)

const (
	testIssuer = "https://example.com/issuer"

	testAudience = "https://test.com/verifier"
	testNonce    = "nonce"
	testSDAlg    = "sha-256"
)

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	selectiveClaims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, selectiveClaims, nil, signer)
	r.NoError(e)
	combinedFormatForIssuance, e := token.Serialize(false)
	r.NoError(e)

	combinedFormatForPresentation := combinedFormatForIssuance + common.CombinedFormatSeparator

	verifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		claims, err := Parse(combinedFormatForPresentation, WithSignatureVerifier(verifier))
		r.NoError(err)
		require.NotNil(t, claims)
		// expected claims iss, exp, iat, nbf, given_name
		// TODO: should we default exp, iat, nbf
		require.Equal(t, 5, len(claims))
	})

	t.Run("success - RS256 signing algorithm", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		v := afjwt.NewRS256Verifier(pubKey)

		rsaToken, err := issuer.New(testIssuer, selectiveClaims, nil, afjwt.NewRS256Signer(privKey, nil))
		r.NoError(err)
		rsaCombinedFormatForIssuance, err := rsaToken.Serialize(false)
		require.NoError(t, err)

		cfp := fmt.Sprintf("%s%s", rsaCombinedFormatForIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfp, WithSignatureVerifier(v))
		r.NoError(err)
		require.Equal(t, 5, len(claims))
	})

	t.Run("success - valid SD-JWT times", func(t *testing.T) {
		now := time.Now()
		oneHourInThePast := now.Add(-time.Hour)
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, selectiveClaims, nil, signer,
			issuer.WithIssuedAt(jwt.NewNumericDate(oneHourInThePast)),
			issuer.WithNotBefore(jwt.NewNumericDate(oneHourInThePast)),
			issuer.WithExpiry(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		cfIssuance, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		cfPresentation := fmt.Sprintf("%s%s", cfIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfPresentation, WithSignatureVerifier(verifier))
		r.NoError(err)
		r.NotNil(claims)
	})

	t.Run("error - signing algorithm not supported", func(t *testing.T) {
		claims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(verifier),
			WithIssuerSigningAlgorithms([]string{}))
		r.Error(err)
		require.Nil(t, claims)
		require.Equal(t, err.Error(), "failed to verify issuer signing algorithm: alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - additional disclosure", func(t *testing.T) {
		claims, err := Parse(fmt.Sprintf("%s~%s~", combinedFormatForIssuance, additionalDisclosure),
			WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(),
			"disclosure digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' not found in SD-JWT disclosure digests")
	})

	t.Run("error - duplicate disclosure", func(t *testing.T) {
		claims, err := Parse(fmt.Sprintf("%s~%s~%s~", combinedFormatForIssuance, additionalDisclosure, additionalDisclosure),
			WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(),
			"check disclosures: duplicate values found [WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd]")
	})

	t.Run("success - with detached payload", func(t *testing.T) {
		jwsParts := strings.Split(combinedFormatForPresentation, ".")
		jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

		jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
		require.NoError(t, err)

		claims, err := Parse(jwsDetached,
			WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
		r.NoError(err)
		r.NotNil(r, claims)
	})

	t.Run("error - invalid claims format", func(t *testing.T) {
		// claims is not JSON
		sdJWTSerialized, err := buildJWS(signer, "not JSON")
		r.NoError(err)

		claims, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "read JWT claims from JWS payload")
		r.Nil(claims)
	})

	t.Run("error - invalid claims(iat)", func(t *testing.T) {
		now := time.Now()
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, selectiveClaims, nil, signer,
			issuer.WithIssuedAt(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		cfi, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		claims, err := Parse(cfi, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"invalid JWT time values: go-jose/go-jose/jwt: validation field, token issued in the future (iat)")
		r.Nil(claims)
	})

	t.Run("error - invalid claims(nbf)", func(t *testing.T) {
		now := time.Now()
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, selectiveClaims, nil, signer,
			issuer.WithNotBefore(jwt.NewNumericDate(oneHourInTheFuture)))
		r.NoError(e)
		cfIssuance, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		cfPresentation := fmt.Sprintf("%s%s", cfIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfPresentation, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"invalid JWT time values: go-jose/go-jose/jwt: validation failed, token not valid yet (nbf)")
		r.Nil(claims)
	})

	t.Run("error - invalid claims(expiry)", func(t *testing.T) {
		now := time.Now()
		oneHourInThePast := now.Add(-time.Hour)

		tokenWithTimes, e := issuer.New(testIssuer, selectiveClaims, nil, signer,
			issuer.WithExpiry(jwt.NewNumericDate(oneHourInThePast)))
		r.NoError(e)
		cfIssuance, e := tokenWithTimes.Serialize(false)
		r.NoError(e)

		cfPresentation := fmt.Sprintf("%s%s", cfIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfPresentation, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"invalid JWT time values: go-jose/go-jose/jwt: validation failed, token is expired (exp)")
		r.Nil(claims)
	})
}

func TestHolderBinding(t *testing.T) {
	r := require.New(t)

	issuerPubKey, issuerPrivateKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(issuerPrivateKey)

	signatureVerifier, e := afjwt.NewEd25519Verifier(issuerPubKey)
	r.NoError(e)

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	holderPubKey, holderPrivKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	holderPublicJWK, e := jwksupport.JWKFromKey(holderPubKey)
	require.NoError(t, e)

	token, e := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithHolderPublicKey(holderPublicJWK))
	r.NoError(e)

	combinedFormatForIssuance, e := token.Serialize(false)
	r.NoError(e)

	_, e = holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
	r.NoError(e)

	holderSigner := afjwt.NewEd25519Signer(holderPrivKey)

	t.Run("success - with holder binding", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.NoError(err)

		// expected claims cnf, iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(6, len(verifiedClaims))
	})

	t.Run("success - with holder binding; expected nonce and audience not specified", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithHolderBindingRequired(true))
		r.NoError(err)

		// expected claims cnf, iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(6, len(verifiedClaims))
	})

	t.Run("success - with holder binding (required)", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithHolderBindingRequired(true),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.NoError(err)

		// expected claims cnf, iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(6, len(verifiedClaims))
	})

	t.Run("error - holder binding required, however not provided by the holder", func(t *testing.T) {
		// holder will not issue holder binding
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"})
		r.NoError(err)

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithHolderBindingRequired(true),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(), "failed to verify holder binding: holder binding is required")
	})

	t.Run("error - holder signature is not matching holder public key in SD-JWT", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: signer, // should have been holder signer; on purpose sign holder binding with wrong signer
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to parse holder binding: parse JWT from compact JWS: ed25519: invalid signature") // nolint:lll
	})

	t.Run("error - invalid holder binding JWT provided by the holder", func(t *testing.T) {
		// holder will not issue holder binding
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"})
		r.NoError(err)

		// add fake holder binding
		combinedFormatForPresentation += "invalid-holder-jwt"

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to parse holder binding: JWT of compacted JWS form is supported only")
	})

	t.Run("error - holder signature algorithm not supported", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithHolderBindingRequired(true),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce),
			WithHolderSigningAlgorithms([]string{}))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to verify holder JWT: failed to verify holder signing algorithm: alg 'EdDSA'") //nolint:lll
	})

	t.Run("error - invalid iat for holder binding", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    "different",
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now().AddDate(1, 0, 0)), // in future
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to verify holder JWT: invalid JWT time values: go-jose/go-jose/jwt: validation field, token issued in the future (iat)") //nolint:lll
	})

	t.Run("error - unexpected nonce for holder binding", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    "different",
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to verify holder JWT: nonce value 'different' does not match expected nonce value 'nonce'") //nolint:lll
	})

	t.Run("error - unexpected audience for holder binding", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: "different",
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to verify holder JWT: audience value 'different' does not match expected audience value 'https://test.com/verifier'") //nolint:lll
	})

	t.Run("error - holder binding provided, however cnf claim not in SD-JWT", func(t *testing.T) {
		tokenWithoutHolderPublicKey, err := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(err)

		cfiWithoutHolderPublicKey, err := tokenWithoutHolderPublicKey.Serialize(false)
		r.NoError(err)

		_, err = holder.Parse(cfiWithoutHolderPublicKey, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		combinedFormatForPresentation, err := holder.DiscloseClaims(cfiWithoutHolderPublicKey, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		verifiedClaims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(signatureVerifier),
			WithExpectedAudienceForHolderBinding(testAudience),
			WithExpectedNonceForHolderBinding(testNonce))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to get signature verifier from presentation claims: cnf must be present in SD-JWT") //nolint:lll
	})

	t.Run("error - holder binding provided, however cnf is not an object", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

		claims := make(map[string]interface{})
		claims["cnf"] = "abc"
		claims["_sd_alg"] = testSDAlg // TODO: Should alg be mandatory if there are no selective disclosures

		sdJWT, err := buildJWS(signer, claims)
		r.NoError(err)

		cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderBinding

		verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to get signature verifier from presentation claims: cnf must be an object") // nolint:lll
	})

	t.Run("error - holder binding provided, cnf is missing jwk", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

		cnf := make(map[string]interface{})
		cnf["test"] = "test"

		claims := make(map[string]interface{})
		claims["cnf"] = cnf
		claims["_sd_alg"] = testSDAlg

		sdJWT, err := buildJWS(signer, claims)
		r.NoError(err)

		cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderBinding

		verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to get signature verifier from presentation claims: jwk must be present in cnf") // nolint:lll
	})

	t.Run("error - holder binding provided, invalid jwk in cnf", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

		cnf := make(map[string]interface{})
		cnf["jwk"] = make(map[string]interface{})

		claims := make(map[string]interface{})
		claims["cnf"] = cnf
		claims["_sd_alg"] = testSDAlg

		sdJWT, err := buildJWS(signer, claims)
		r.NoError(err)

		cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderBinding

		verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to get signature verifier from presentation claims: unmarshal jwk: unable to read jose JWK, go-jose/go-jose: unknown json web key type ''") // nolint:lll
	})

	t.Run("error - holder binding provided, invalid jwk in cnf", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

		cnf := make(map[string]interface{})
		cnf["jwk"] = make(map[string]interface{})

		claims := make(map[string]interface{})
		claims["cnf"] = cnf
		claims["_sd_alg"] = testSDAlg

		sdJWT, err := buildJWS(signer, claims)
		r.NoError(err)

		cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderBinding

		verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to get signature verifier from presentation claims: unmarshal jwk: unable to read jose JWK, go-jose/go-jose: unknown json web key type ''") // nolint:lll
	})

	t.Run("error - holder binding provided with EdDSA, jwk in cnf is RSA", func(t *testing.T) {
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

		claims := make(map[string]interface{})
		claims["cnf"] = map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": "RSA",
				"e":   "AQAB",
				"n":   "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11",
			},
		}

		claims["_sd_alg"] = testSDAlg

		sdJWT, err := buildJWS(signer, claims)
		r.NoError(err)

		cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderBinding

		verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
		r.Error(err)
		r.Nil(verifiedClaims)

		r.Contains(err.Error(),
			"failed to verify holder binding: failed to parse holder binding: parse JWT from compact JWS: no verifier found for EdDSA algorithm") // nolint:lll
	})
}

func TestVerifySigningAlgorithm(t *testing.T) {
	r := require.New(t)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := verifySigningAlg(headers, []string{"EdDSA"})
		r.NoError(err)
	})

	t.Run("error - signing algorithm can not be empty", func(t *testing.T) {
		headers := make(afjose.Headers)
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "missing alg")
	})

	t.Run("success - EdDSA signing algorithm not in allowed list", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - signing algorithm can not be none", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "none"
		err := verifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg value cannot be 'none'")
	})
}

func TestGetVerifiedPayload(t *testing.T) {
	r := require.New(t)

	_, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	selectiveClaims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, selectiveClaims, nil, signer)
	r.NoError(e)

	t.Run("success", func(t *testing.T) {
		claims, err := getVerifiedPayload(token.Disclosures, token.SignedJWT)
		r.NoError(err)
		r.NotNil(claims)
		r.Equal(5, len(claims))
	})

	t.Run("error - invalid disclosure(not encoded)", func(t *testing.T) {
		claims, err := getVerifiedPayload([]string{"xyz"}, token.SignedJWT)
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(),
			"failed to get verified claims: failed to unmarshal disclosure array: invalid character")
	})
}

func TestWithJWTDetachedPayload(t *testing.T) {
	detachedPayloadOpt := WithJWTDetachedPayload([]byte("payload"))
	require.NotNil(t, detachedPayloadOpt)

	opts := &parseOpts{}
	detachedPayloadOpt(opts)
	require.Equal(t, []byte("payload"), opts.detachedPayload)
}

func buildJWS(signer afjose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := afjose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

const additionalDisclosure = `WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`
