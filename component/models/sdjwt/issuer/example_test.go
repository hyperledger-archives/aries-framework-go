/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
)

func ExampleNew() {
	signer, _, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err.Error())
	}

	claims := map[string]interface{}{
		"last_name": "Smith",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"country":        "US",
		},
	}

	// Issuer will issue SD-JWT for specified claims. Salt function is only provided to keep example outcome the same.
	token, err := New("https://example.com/issuer", claims, nil, signer,
		WithStructuredClaims(true),
		WithNonSelectivelyDisclosableClaims([]string{"address.country"}),
		WithSaltFnc(func() (string, error) {
			return sampleSalt, nil
		}))
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	var decoded map[string]interface{}

	err = token.DecodeClaims(&decoded)
	if err != nil {
		fmt.Println("failed to decode SD-JWT claims: %w", err.Error())
	}

	issuerClaimsJSON, err := marshalObj(decoded)
	if err != nil {
		fmt.Println("verifier failed to marshal verified claims: %w", err.Error())
	}

	fmt.Println(issuerClaimsJSON)

	// Output: {
	//	"_sd": [
	//		"V9-Eiizd3iJpdlxojQuwps44Zba7z6R08S7rPCDg_wU"
	//	],
	//	"_sd_alg": "sha-256",
	//	"address": {
	//		"_sd": [
	//			"tD1XVFffEo0KTGuvHn9UlXCBgt3vot5xAanqXMdvVMg"
	//		],
	//		"country": "US"
	//	},
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

func marshalObj(obj interface{}) (string, error) {
	objBytes, err := json.Marshal(obj)
	if err != nil {
		fmt.Println("failed to marshal object: %w", err.Error())
	}

	return prettyPrint(objBytes)
}
