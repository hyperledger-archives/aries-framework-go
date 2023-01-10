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

	"github.com/stretchr/testify/require"

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

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	signatureVerifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success", func(t *testing.T) {
		// Issuer will issue SD-JWT for specified claims.
		token, e := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(e)

		// TODO: Should we have one call instead of two (designed based on JWT)
		combinedFormatForIssuance, e := token.Serialize(false)
		r.NoError(e)

		fmt.Println(fmt.Sprintf("issuer SD-JWT: %s", combinedFormatForIssuance))

		// Holder will parse combined format for issuance and hold on to that
		// combined format for issuance and the claims that can be selected.
		claims, err := holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(signatureVerifier))
		r.NoError(err)

		// expected disclosures given_name and last_name
		r.Equal(2, len(claims))

		// Holder will disclose only sub-set of claims to verifier.
		combinedFormatForPresentation, err := holder.DiscloseClaims(combinedFormatForIssuance, []string{"given_name"})
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
}
