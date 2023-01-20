/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdjwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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

	t.Run("success - simple claims (flat option)", func(t *testing.T) {
		// Issuer will issue SD-JWT for specified claims.
		token, err := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(err)

		var simpleClaimsFlatOption map[string]interface{}
		err = token.DecodeClaims(&simpleClaimsFlatOption)
		r.NoError(err)

		printObject(t, "Simple Claims:", simpleClaimsFlatOption)

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

		selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name"}, claims)

		// Holder will disclose only sub-set of claims to verifier.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("holder SD-JWT: %s", combinedFormatForPresentation))

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
			verifier.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)
		r.NotNil(verifiedClaims)

		printObject(t, "Verified Claims", verifiedClaims)

		// expected claims iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(5, len(verifiedClaims))
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

		selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name"}, claims)

		// Holder will disclose only sub-set of claims to verifier and add holder binding.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures,
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

		printObject(t, "Verified Claims", verifiedClaims)

		// expected claims cnf, iss, exp, iat, nbf, given_name; last_name was not disclosed
		r.Equal(6, len(verifiedClaims))
	})

	t.Run("success - complex claims object with structured claims option", func(t *testing.T) {
		complexClaims := createComplexClaims()

		// Issuer will issue SD-JWT for specified claims. We will use structured(nested) claims in this test.
		token, err := issuer.New(testIssuer, complexClaims, nil, signer,
			issuer.WithStructuredClaims(true))
		r.NoError(err)

		var structuredClaims map[string]interface{}
		err = token.DecodeClaims(&structuredClaims)
		r.NoError(err)

		printObject(t, "Complex Claims(Structured Option) :", structuredClaims)

		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", combinedFormatForIssuance))

		// Holder will parse combined format for issuance and hold on to that
		// combined format for issuance and the claims that can be selected.
		claims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		printObject(t, "Holder Claims", claims)

		r.Equal(10, len(claims))

		selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name", "email", "street_address"}, claims)

		// Holder will disclose only sub-set of claims to verifier.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("holder SD-JWT: %s", combinedFormatForPresentation))

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
			verifier.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected claims iss, exp, iat, nbf, given_name, email, street_address
		r.Equal(7, len(verifiedClaims))

		printObject(t, "Verified Claims", verifiedClaims)
	})

	t.Run("success - complex claims object with flat claims option", func(t *testing.T) {
		complexClaims := createComplexClaims()

		// Issuer will issue SD-JWT for specified claims. We will use structured(nested) claims in this test.
		token, err := issuer.New(testIssuer, complexClaims, nil, signer)
		r.NoError(err)

		var flatClaims map[string]interface{}
		err = token.DecodeClaims(&flatClaims)
		r.NoError(err)

		printObject(t, "Complex Claims (Flat Option)", flatClaims)

		combinedFormatForIssuance, err := token.Serialize(false)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", combinedFormatForIssuance))

		// Holder will parse combined format for issuance and hold on to that
		// combined format for issuance and the claims that can be selected.
		claims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		printObject(t, "Holder Claims", claims)

		r.Equal(7, len(claims))

		selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name", "email", "address"}, claims)

		// Holder will disclose only sub-set of claims to verifier.
		combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures)
		r.NoError(err)

		fmt.Println(fmt.Sprintf("holder SD-JWT: %s", combinedFormatForPresentation))

		// Verifier will validate combined format for presentation and create verified claims.
		verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
			verifier.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected claims iss, exp, iat, nbf, given_name, email, street_address
		r.Equal(7, len(verifiedClaims))

		printObject(t, "Verified Claims", verifiedClaims)
	})
}

func createComplexClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	return claims
}

func getDisclosuresFromClaimNames(selectedClaimNames []string, claims []*holder.Claim) []string {
	var disclosures []string

	for _, c := range claims {
		if contains(selectedClaimNames, c.Name) {
			disclosures = append(disclosures, c.Disclosure)
		}
	}

	return disclosures
}

func contains(values []string, val string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}

	return false
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
