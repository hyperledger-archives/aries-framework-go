/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
Package verifier enables the Verifier: An entity that requests, checks and
extracts the claims from an SD-JWT and respective Disclosures.
*/
package verifier

import (
	"fmt"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

// parseV5 parses combined format for presentation and returns verified claims.
// The Verifier has to verify that all disclosed claim values were part of the original, Issuer-signed SD-JWT.
//
// At a high level, the Verifier:
//   - receives the Combined Format for Presentation from the Holder and verifies the signature of the SD-JWT using the
//     Issuer's public key,
//   - verifies the Key Binding JWT, if Key Binding is required by the Verifier's policy,
//     using the public key included in the SD-JWT,
//   - calculates the digests over the Holder-Selected Disclosures and verifies that each digest
//     is contained in the SD-JWT.
//
// Detailed algorithm:
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-verification-by-the-verifie
//
// The Verifier will not, however, learn any claim values not disclosed in the Disclosures.
func parseV5(cfp *common.CombinedFormatForPresentation, signedJWT *afgjwt.JSONWebToken, opts ...common.ParseOpt) (map[string]interface{}, error) {
	err := verifyKeyBinding(signedJWT, cfp.HolderBinding, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify holder binding: %w", err)
	}

	// Process the Disclosures and embedded digests in the issuser-signed JWT.
	// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-4.3.1
	return getDisclosedClaims(cfp.Disclosures, signedJWT, common.SDJWTVersionV5)
}

func verifyKeyBinding(sdJWT *afgjwt.JSONWebToken, keyBinding string, opts ...common.ParseOpt) error {
	// TODO: add key binding code
	// spec: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.3-3
	return verifyHolderBinding(sdJWT, keyBinding, opts...)
}
