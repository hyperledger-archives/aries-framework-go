/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/verifier"
)

const (
	testIssuer = "https://example.com/issuer"
)

func TestSDJWTFlow(t *testing.T) {
	r := require.New(t)

	issuerPublicKey, issuerPrivateKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(issuerPrivateKey)

	signatureVerifier, e := afjwt.NewEd25519Verifier(issuerPublicKey)
	r.NoError(e)

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	t.Run("success", func(t *testing.T) {
		// Issuer will issue SD-JWT for specified claims.
		token, err := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(err)

		// TODO: Should we have one call instead of two (designed based on JWT)
		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", combinedFormatForIssuance))

		// Holder will parse combined format for issuance and hold on to that
		// combined format for issuance and the claims that can be selected.
		claims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected disclosures given_name and last_name
		r.Equal(2, len(claims))

		// Holder will disclose only sub-set of claims to verifier.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance,
			[]string{claims[0].Disclosure})
		r.NoError(err)

		fmt.Println(fmt.Sprintf("holder SD-JWT: %s", combinedFormatForPresentation))

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
			verifier.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected claims iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(5, len(verifiedClaims))

		fmt.Println(fmt.Sprintf("verified claims: %+v", verifiedClaims))
	})

	t.Run("success - with holder binding", func(t *testing.T) {
		holderPublicKey, holderPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		// Issuer will issue SD-JWT for specified claims and holder public key.
		token, err := issuer.New(testIssuer, claims, nil, signer,
			issuer.WithHolderPublicKey(holderPublicJWK))
		r.NoError(err)

		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", combinedFormatForIssuance))

		// Holder will parse combined format for issuance and hold on to that
		// combined format for issuance and the claims that can be selected.
		claims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected disclosures given_name and last_name
		r.Equal(2, len(claims))

		holderSigner := afjwt.NewEd25519Signer(holderPrivateKey)

		const testAudience = "https://test.com/verifier"
		const testNonce = "nonce"

		// Holder will disclose only sub-set of claims to verifier and add holder binding.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance,
			[]string{claims[0].Disclosure},
			holder.WithHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    testNonce,
					Audience: testAudience,
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)

		fmt.Println(fmt.Sprintf("holder SD-JWT: %s", combinedFormatForPresentation))

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
			verifier.WithSignatureVerifier(signatureVerifier),
			verifier.WithHolderBindingRequired(true),
			verifier.WithExpectedAudienceForHolderBinding(testAudience),
			verifier.WithExpectedNonceForHolderBinding(testNonce))
		r.NoError(err)

		fmt.Println(fmt.Sprintf("verified claims: %+v", verifiedClaims))

		// expected claims cnf, iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(6, len(verifiedClaims))
	})
}
