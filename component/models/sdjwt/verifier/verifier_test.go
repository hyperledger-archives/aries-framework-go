/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"bytes"
	"crypto"
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

	afjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/issuer"
)

const (
	testIssuer = "https://example.com/issuer"

	testAudience = "https://test.com/verifier"
	testNonce    = "nonce"
	testSDAlg    = "sha-256"

	year = 365 * 24 * 60 * time.Minute
)

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	selectiveClaims := map[string]interface{}{"given_name": "Albert"}

	now := time.Now()

	var timeOpts []issuer.NewOpt
	timeOpts = append(timeOpts,
		issuer.WithNotBefore(jwt.NewNumericDate(now)),
		issuer.WithIssuedAt(jwt.NewNumericDate(now)),
		issuer.WithExpiry(jwt.NewNumericDate(now.Add(year))),
		issuer.WithSDJWTVersion(common.SDJWTVersionV2))

	headers := afjose.Headers{
		afjose.HeaderType: "JWT",
	}

	token, e := issuer.New(testIssuer, selectiveClaims, headers, signer, timeOpts...)
	r.NoError(e)
	combinedFormatForIssuance, e := token.Serialize(false)
	r.NoError(e)

	combinedFormatForPresentation := combinedFormatForIssuance + common.CombinedFormatSeparator

	verifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		claims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(verifier),
			WithExpectedTypHeader("JWT"))
		r.NoError(err)
		require.NotNil(t, claims)

		// expected claims iss, exp, iat, nbf, given_name
		require.Equal(t, 5, len(claims))
	})

	t.Run("success - VC sample", func(t *testing.T) {
		token, _, err := afjwt.Parse(vcSDJWT, afjwt.WithSignatureVerifier(&holder.NoopSignatureVerifier{}))
		r.NoError(err)

		var payload map[string]interface{}
		err = token.DecodeClaims(&payload)
		r.NoError(err)

		printObject(t, "SD-JWT Payload with VC", payload)

		vcCombinedFormatForPresentation := vcCombinedFormatForIssuance + common.CombinedFormatSeparator
		claims, err := Parse(vcCombinedFormatForPresentation, WithSignatureVerifier(&holder.NoopSignatureVerifier{}))
		r.NoError(err)

		printObject(t, "Disclosed Claims with VC", claims)

		// expected claims iat, iss, jti, nbf, sub, vc
		require.Equal(t, 6, len(claims))
	})

	t.Run("success - RS256 signing algorithm", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		v := afjwt.NewRS256Verifier(pubKey)

		rsaToken, err := issuer.New(testIssuer, selectiveClaims, headers, afjwt.NewRS256Signer(privKey, nil))
		r.NoError(err)
		rsaCombinedFormatForIssuance, err := rsaToken.Serialize(false)
		require.NoError(t, err)

		cfp := fmt.Sprintf("%s%s", rsaCombinedFormatForIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfp, WithSignatureVerifier(v), WithExpectedTypHeader("JWT"))
		r.NoError(err)

		// expected claims iss, given_name
		require.Equal(t, 2, len(claims))
		printObject(t, "claims", claims)
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

	t.Run("error - unexpected typ header", func(t *testing.T) {
		claims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(verifier),
			WithExpectedTypHeader("vc-sd+jwt"))
		r.Error(err)
		require.Nil(t, claims)
		require.Equal(t, err.Error(), "failed to verify typ header: unexpected typ \"JWT\"")
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

func TestHolderVerification(t *testing.T) {
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

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	claimsToDisclose := []string{cfi.Disclosures[0]}

	tests := []struct {
		name    string
		headers afjose.Headers
	}{
		{
			name:    "holder binding",
			headers: nil,
		},
		{
			name: "key binding",
			headers: map[string]interface{}{
				afjose.HeaderType: "kb+jwt",
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Run("success", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderBinding(testAudience),
					WithExpectedNonceForHolderBinding(testNonce),
					WithLeewayForClaimsValidation(time.Hour))
				r.NoError(err)

				// expected claims cnf, iss, given_name; last_name was not disclosed
				r.Equal(3, len(verifiedClaims))
			})

			t.Run("success - expected nonce and audience not specified", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithHolderBindingRequired(true))
				r.NoError(err)

				// expected claims cnf, iss, given_name; last_name was not disclosed
				r.Equal(3, len(verifiedClaims))
			})

			t.Run("success (required)", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				// Verifier will validate combined format for presentation and create verified claims.
				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithHolderVerificationRequired(true),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.NoError(err)

				// expected claims cnf, iss, given_name; last_name was not disclosed
				r.Equal(3, len(verifiedClaims))
			})

			t.Run("error - holder verification required, however not provided by the holder", func(t *testing.T) {
				// holder will not issue holder binding
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose)
				r.NoError(err)

				// Verifier will validate combined format for presentation and create verified claims.
				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithHolderVerificationRequired(true),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(), "run holder verification: holder verification is required")
			})

			t.Run("error - holder signature is not matching holder public key in SD-JWT", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  signer, // should have been holder signer; on purpose sign holder binding with wrong signer
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"parse JWT from compact JWS: ed25519: invalid signature") // nolint:lll
			})

			t.Run("error - invalid holder verification JWT provided by the holder", func(t *testing.T) {
				// holder will not issue holder verification
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose)
				r.NoError(err)

				// add fake holder binding
				combinedFormatForPresentation += "invalid-holder-jwt"

				// Verifier will validate combined format for presentation and create verified claims.
				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"parse holder verification JWT: JWT of compacted JWS form is supported only")
			})

			t.Run("error - holder signature algorithm not supported", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				// Verifier will validate combined format for presentation and create verified claims.
				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithHolderVerificationRequired(true),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce),
					WithHolderSigningAlgorithms([]string{}))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"failed to verify holder signing algorithm: alg 'EdDSA' is not in the allowed list") //nolint:lll
			})

			t.Run("error - invalid iat", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    "different",
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now().AddDate(1, 0, 0)), // in future
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"verify holder JWT: invalid JWT time values: go-jose/go-jose/jwt: validation field, token issued in the future (iat)") //nolint:lll
			})

			t.Run("error - unexpected nonce", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    "different",
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: verify holder JWT: nonce value 'different' does not match expected nonce value 'nonce'") //nolint:lll
			})

			t.Run("error - unexpected audience", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: "different",
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: verify holder JWT: audience value 'different' does not match expected audience value 'https://test.com/verifier'") //nolint:lll
			})

			t.Run("error - holder verification provided, however cnf claim not in SD-JWT", func(t *testing.T) {
				tokenWithoutHolderPublicKey, err := issuer.New(testIssuer, claims, nil, signer)
				r.NoError(err)

				cfiWithoutHolderPublicKey, err := tokenWithoutHolderPublicKey.Serialize(false)
				r.NoError(err)

				ctd := []string{common.ParseCombinedFormatForIssuance(cfiWithoutHolderPublicKey).Disclosures[0]}

				_, err = holder.Parse(cfiWithoutHolderPublicKey, holder.WithSignatureVerifier(signatureVerifier))
				r.NoError(err)

				combinedFormatForPresentation, err := holder.CreatePresentation(cfiWithoutHolderPublicKey, ctd,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(signatureVerifier),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: failed to get signature verifier from presentation claims: cnf must be present in SD-JWT") //nolint:lll
			})

			t.Run("error - holder verification provided, however cnf is not an object", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				r.NoError(err)

				cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

				claims := make(map[string]interface{})
				claims["cnf"] = "abc"
				claims["_sd_alg"] = testSDAlg

				sdJWT, err := buildJWS(signer, claims)
				r.NoError(err)

				cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderVerification

				verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: failed to get signature verifier from presentation claims: cnf must be an object") // nolint:lll
			})

			t.Run("error - holder verification provided, cnf is missing jwk", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
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

				cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderVerification

				verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: failed to get signature verifier from presentation claims: jwk must be present in cnf") // nolint:lll
			})

			t.Run("error - holder verification provided, invalid jwk in cnf", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
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

				cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderVerification

				verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: failed to get signature verifier from presentation claims: unmarshal jwk: unable to read jose JWK, go-jose/go-jose: unknown json web key type ''") // nolint:lll
			})

			t.Run("error - holder verification provided, invalid jwk in cnf", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
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

				cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderVerification

				verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: failed to get signature verifier from presentation claims: unmarshal jwk: unable to read jose JWK, go-jose/go-jose: unknown json web key type ''") // nolint:lll
			})

			t.Run("error - holder verification provided with EdDSA, jwk in cnf is RSA", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: jwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
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

				cfpWithInvalidCNF := sdJWT + common.CombinedFormatSeparator + cfp.HolderVerification

				verifiedClaims, err := Parse(cfpWithInvalidCNF, WithSignatureVerifier(signatureVerifier))
				r.Error(err)
				r.Nil(verifiedClaims)

				r.Contains(err.Error(),
					"run holder verification: parse holder verification JWT: parse JWT from compact JWS: no verifier found for EdDSA algorithm") // nolint:lll
			})
		})
	}
}

func TestGetVerifiedPayload(t *testing.T) {
	r := require.New(t)

	_, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	selectiveClaims := map[string]interface{}{"given_name": "Albert"}

	now := time.Now()

	var timeOpts []issuer.NewOpt
	timeOpts = append(timeOpts,
		issuer.WithNotBefore(jwt.NewNumericDate(now)),
		issuer.WithIssuedAt(jwt.NewNumericDate(now)),
		issuer.WithExpiry(jwt.NewNumericDate(now.Add(year))))

	token, e := issuer.New(testIssuer, selectiveClaims, nil, signer, timeOpts...)
	r.NoError(e)

	t.Run("success V2", func(t *testing.T) {
		claims, err := getDisclosedClaims(token.Disclosures, token.SignedJWT, crypto.SHA256)
		r.NoError(err)
		r.NotNil(claims)
		r.Equal(5, len(claims))

		printObject(t, "Disclosed Claims", claims)
	})

	t.Run("success V5", func(t *testing.T) {
		claims, err := getDisclosedClaims(token.Disclosures, token.SignedJWT, crypto.SHA256)
		r.NoError(err)
		r.NotNil(claims)
		r.Equal(5, len(claims))

		printObject(t, "Disclosed Claims", claims)
	})

	t.Run("error - invalid disclosure(not encoded)", func(t *testing.T) {
		claims, err := getDisclosedClaims([]string{"xyz"}, token.SignedJWT, crypto.SHA256)
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(),
			"failed to get verified payload: failed to unmarshal disclosure array: invalid character")
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

func printObject(t *testing.T, name string, obj interface{}) {
	t.Helper()

	objBytes, err := json.Marshal(obj)
	require.NoError(t, err)

	prettyJSON, err := prettyPrint(objBytes)
	require.NoError(t, err)

	fmt.Println(name + ":")
	fmt.Println(prettyJSON)
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

const additionalDisclosure = `WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`

const vcCombinedFormatForIssuance = `eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjEuNjczOTg3NTQ3ZSswOSwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEuNjczOTg3NTQ3ZSswOSwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDlYemtRbVJMQncxSXpfeHVGUmVLMUItRmpCdTdjT0N3RTlOR2F1d251SSJ9fSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbInBBdjJUMU10YmRXNGttUUdxT1VVRUpjQmdTZi1mSFRHV2xQVUV4aWlIbVEiLCI2dDlBRUJCQnEzalZwckJ3bGljOGhFWnNNSmxXSXhRdUw5c3ExMzJZTnYwIl0sImRlZ3JlZSI6eyJfc2QiOlsibzZzV2h4RjcxWHBvZ1cxVUxCbU90bjR1SXFGdjJ3ODF6emRuelJXdlpqYyIsIi1yRklXbU1YR3ZXX0FIYVEtODhpMy11ZzRUVjhLUTg5TjdmZmtneFc2X2MiXX0sImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIn0sImZpcnN0X25hbWUiOiJGaXJzdCBuYW1lIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMTg3MiIsImluZm8iOiJJbmZvIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0xN1QyMjozMjoyNy40NjgxMDk4MTcrMDI6MDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJsYXN0X25hbWUiOiJMYXN0IG5hbWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX0.GcfSA6NkONxdsm5Lxj9-988eWx1ZvMz5vJ1uh2x8UK1iKIeQLmhsWpA_34RbtAm2HnuoxW4_ZGeiHBzQ1GLTDQ~WyJFWkVDRVZ1YWVJOXhZWmlWb3VMQldBIiwidHlwZSIsIkJhY2hlbG9yRGVncmVlIl0~WyJyMno1UzZMa25FRTR3TWwteFB0VEx3IiwiZGVncmVlIiwiTUlUIl0~WyJ2VkhfaGhNQy1aSUt5WFdtdDUyOWpnIiwic3BvdXNlIiwiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIl0~WyJrVzh0WVVwbVl1VmRoZktFT050TnFnIiwibmFtZSIsIkpheWRlbiBEb2UiXQ` // nolint: lll
const vcSDJWT = `eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjEuNjczOTg3NTQ3ZSswOSwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEuNjczOTg3NTQ3ZSswOSwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDlYemtRbVJMQncxSXpfeHVGUmVLMUItRmpCdTdjT0N3RTlOR2F1d251SSJ9fSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbInBBdjJUMU10YmRXNGttUUdxT1VVRUpjQmdTZi1mSFRHV2xQVUV4aWlIbVEiLCI2dDlBRUJCQnEzalZwckJ3bGljOGhFWnNNSmxXSXhRdUw5c3ExMzJZTnYwIl0sImRlZ3JlZSI6eyJfc2QiOlsibzZzV2h4RjcxWHBvZ1cxVUxCbU90bjR1SXFGdjJ3ODF6emRuelJXdlpqYyIsIi1yRklXbU1YR3ZXX0FIYVEtODhpMy11ZzRUVjhLUTg5TjdmZmtneFc2X2MiXX0sImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIn0sImZpcnN0X25hbWUiOiJGaXJzdCBuYW1lIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMTg3MiIsImluZm8iOiJJbmZvIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0xN1QyMjozMjoyNy40NjgxMDk4MTcrMDI6MDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJsYXN0X25hbWUiOiJMYXN0IG5hbWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX0.GcfSA6NkONxdsm5Lxj9-988eWx1ZvMz5vJ1uh2x8UK1iKIeQLmhsWpA_34RbtAm2HnuoxW4_ZGeiHBzQ1GLTDQ`                                                                                                                                                                                                                                                                                                                        // nolint:lll
