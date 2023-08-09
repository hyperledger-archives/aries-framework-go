/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/issuer"
)

func ExampleParse() {
	signer, signatureVerifier, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	// Issuer will issue SD-JWT for specified claims. Salt function is only provided to keep example outcome the same.
	token, err := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithSaltFnc(func() (string, error) {
			return "3jqcb67z9wks08zwiK7EyQ", nil
		}))
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance and hold on to that
	// combined format for issuance and the claims that can be selected.
	holderClaims, err := Parse(combinedFormatForIssuance, WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// Sort by claim name, keeping original order or equal elements.
	sort.SliceStable(holderClaims, func(i, j int) bool {
		return holderClaims[i].Name < holderClaims[j].Name
	})

	holderClaimsJSON, err := marshalObj(holderClaims)
	if err != nil {
		fmt.Println("verifier failed to marshal holder claims: %w", err.Error())
	}

	fmt.Println(holderClaimsJSON)

	// Output: [
	//	{
	//		"Disclosure": "WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwiZ2l2ZW5fbmFtZSIsIkFsYmVydCJd",
	//		"Name": "given_name",
	//		"Value": "Albert"
	//	},
	//	{
	//		"Disclosure": "WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwibGFzdF9uYW1lIiwiU21pdGgiXQ",
	//		"Name": "last_name",
	//		"Value": "Smith"
	//	}
	// ]
}

func ExampleCreatePresentation() {
	signer, signatureVerifier, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	holderSigner, holderJWK, err := setUpHolderBinding()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	// Issuer will issue SD-JWT for specified claims and holder public key.
	token, err := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithHolderPublicKey(holderJWK))
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance and hold on to that
	// combined format for issuance and the claims that can be selected.
	holderClaims, err := Parse(combinedFormatForIssuance, WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// The Holder will only select given_name
	selectedDisclosures := getDisclosuresFromClaimNames([]string{"given_name"}, holderClaims)

	// Holder will disclose only sub-set of claims to verifier and create holder binding for the verifier.
	combinedFormatForPresentation, err := CreatePresentation(combinedFormatForIssuance, selectedDisclosures,
		WithHolderVerification(&BindingInfo{
			Payload: BindingPayload{
				Nonce:    "nonce",
				Audience: "https://test.com/verifier",
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			Signer: holderSigner,
		}))
	if err != nil {
		fmt.Println("holder failed to create presentation: %w", err.Error())
	}

	cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

	fmt.Println(cfp.HolderVerification != "")

	// Output: true
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

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getDisclosuresFromClaimNames(selectedClaimNames []string, claims []*Claim) []string {
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
