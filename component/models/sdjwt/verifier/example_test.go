/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
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

	// Issuer will issue SD-JWT for specified claims.
	token, err := issuer.New(testIssuer, claims, nil, signer)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	combinedFormatForIssuance, err := token.Serialize(false)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err.Error())
	}

	// Holder will parse combined format for issuance for verification purposes.
	_, err = holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		fmt.Println("holder failed to parse SD-JWT: %w", err.Error())
	}

	// The Holder will disclose all claims.
	combinedFormatForPresentation := combinedFormatForIssuance + common.CombinedFormatSeparator

	// Verifier will validate combined format for presentation and create verified claims.
	verifiedClaims, err := Parse(combinedFormatForPresentation,
		WithSignatureVerifier(signatureVerifier))
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
	//	"iss": "https://example.com/issuer",
	//	"last_name": "Smith"
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
