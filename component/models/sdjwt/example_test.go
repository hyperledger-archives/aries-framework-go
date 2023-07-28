/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/issuer"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/verifier"
)

func ExampleSimpleClaims() { //nolint:govet
	signer, signatureVerifier, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	// Issuer will issue SD-JWT for specified claims.
	token, err := issuer.New(testIssuer, claims, nil, signer)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance and hold on to that
	// combined format for issuance and the claims that can be selected.
	holderClaims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// The Holder will only select given_name
	selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name"}, holderClaims)

	// Holder will disclose only sub-set of claims to verifier.
	combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures)
	if err != nil {
		fmt.Println("holder failed to create presentation: %w", err.Error())
	}

	// Verifier will validate combined format for presentation and create verified claims.
	verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
		verifier.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("verifier failed to parse holder presentation: %w", err.Error())
	}

	verifiedClaimsJSON, err := marshalObj(verifiedClaims)
	if err != nil {
		fmt.Println("verifier failed to marshal verified claims: %w", err.Error())
	}

	fmt.Println(verifiedClaimsJSON)

	// Output: {
	//	"given_name": "Albert",
	//	"iss": "https://example.com/issuer"
	// }
}

func ExampleComplexClaimsWithHolderBinding() { //nolint:govet
	signer, signatureVerifier, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	holderSigner, holderJWK, err := setUpHolderBinding()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

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

	// Issuer will issue SD-JWT for specified claims. Structured claims not selected as an option hence complex object
	// address will be treated as an object not as a set of properties. Holder public key is provided therefore it will
	// be added as "cnf" claim.
	token, err := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithHolderPublicKey(holderJWK),
	)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance and hold on to that
	// combined format for issuance and the claims that can be selected.
	holderClaims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// The Holder will only select given_name, address
	selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name", "address"}, holderClaims)

	// Holder will disclose only sub-set of claims to verifier.
	combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures,
		holder.WithHolderVerification(&holder.BindingInfo{
			Payload: holder.BindingPayload{
				Nonce:    "nonce",
				Audience: "https://test.com/verifier",
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			Signer: holderSigner,
		}))
	if err != nil {
		fmt.Println("holder failed to create presentation: %w", err.Error())
	}

	// Verifier will validate combined format for presentation and create verified claims.
	verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
		verifier.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("verifier failed to parse holder presentation: %w", err.Error())
	}

	addressClaimsJSON, err := marshalObj(verifiedClaims["address"])
	if err != nil {
		fmt.Println("verifier failed to marshal verified claims: %w", err.Error())
	}

	fmt.Println(addressClaimsJSON)

	// Output: {
	//	"country": "US",
	//	"locality": "Anytown",
	//	"region": "Anystate",
	//	"street_address": "123 Main St"
	// }
}

func ExampleComplexObjectWithStructuredClaims() { //nolint:govet
	signer, signatureVerifier, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

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

	// Issuer will issue SD-JWT for specified claims.
	token, err := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithStructuredClaims(true),
		issuer.WithNonSelectivelyDisclosableClaims([]string{"address.country"}),
	)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance and hold on to that
	// combined format for issuance and the claims that can be selected.
	holderClaims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// The Holder will only select given_name, street_address
	selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name", "street_address"}, holderClaims)

	// Holder will disclose only sub-set of claims to verifier.
	combinedFormatForPresentation, err := holder.CreatePresentation(combinedFormatForIssuance, selectedDisclosures)
	if err != nil {
		fmt.Println("holder failed to create presentation: %w", err.Error())
	}

	// Verifier will validate combined format for presentation and create verified claims.
	verifiedClaims, err := verifier.Parse(combinedFormatForPresentation,
		verifier.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("verifier failed to parse holder presentation: %w", err.Error())
	}

	verifiedClaimsJSON, err := marshalObj(verifiedClaims)
	if err != nil {
		fmt.Println("verifier failed to marshal verified claims: %w", err.Error())
	}

	fmt.Println(verifiedClaimsJSON)

	// Output: {
	//	"address": {
	//		"country": "US",
	//		"street_address": "123 Main St"
	//	},
	//	"given_name": "John",
	//	"iss": "https://example.com/issuer"
	// }
}
func setUp() (*afjwt.JoseED25519Signer, *afjwt.JoseEd25519Verifier, error) {
	issuerPublicKey, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signer := afjwt.NewEd25519Signer(issuerPrivateKey)

	signatureVerifier, err := afjwt.NewEd25519Verifier(issuerPublicKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, signatureVerifier, nil
}

func setUpHolderBinding() (*afjwt.JoseED25519Signer, *jwk.JWK, error) {
	holderPublicKey, holderPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
	if err != nil {
		return nil, nil, err
	}

	holderSigner := afjwt.NewEd25519Signer(holderPrivateKey)

	return holderSigner, holderPublicJWK, nil
}

func marshalObj(obj interface{}) (string, error) {
	objBytes, err := json.Marshal(obj)
	if err != nil {
		fmt.Println("failed to marshal object: %w", err.Error())
	}

	return prettyPrint(objBytes)
}
