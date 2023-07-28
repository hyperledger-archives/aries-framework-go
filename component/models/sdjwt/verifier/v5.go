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

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
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
	err := verifyKeyBinding(signedJWT, cfp.HolderVerification, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to verify holder binding: %w", err)
	}

	// Process the Disclosures and embedded digests in the issuser-signed JWT.
	// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-4.3.1
	return getDisclosedClaims(cfp.Disclosures, signedJWT, common.SDJWTVersionV5)
}

func verifyKeyBinding(sdJWT *afgjwt.JSONWebToken, keyBinding string, opts ...common.ParseOpt) error {
	// spec: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.3-3
	defaultSigningAlgorithms := []string{"EdDSA", "RS256"}
	pOpts := &common.ParseOpts{
		HolderSigningAlgorithms:   defaultSigningAlgorithms,
		LeewayForClaimsValidation: jwt.DefaultLeeway,
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	if pOpts.HolderVerificationRequired && keyBinding == "" {
		return fmt.Errorf("key binding is required")
	}

	if keyBinding == "" {
		// not required and not present - nothing to do
		return nil
	}

	signatureVerifier, err := getSignatureVerifier(utils.CopyMap(sdJWT.Payload))
	if err != nil {
		return fmt.Errorf("failed to get signature verifier from presentation claims: %w", err)
	}

	// Validate the signature over the Key Binding JWT.
	holderJWT, _, err := afgjwt.Parse(keyBinding,
		afgjwt.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		return fmt.Errorf("failed to parse key binding: %w", err)
	}

	err = verifyKeyBindingJWT(holderJWT, pOpts)
	if err != nil {
		return fmt.Errorf("failed to verify holder JWT: %w", err)
	}

	return nil
}

func verifyKeyBindingJWT(holderJWT *afgjwt.JSONWebToken, pOpts *common.ParseOpts) error {
	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err := verifySigningAlg(holderJWT.Headers, pOpts.HolderSigningAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to verify holder signing algorithm: %w", err)
	}

	// Check that the typ of the Key Binding JWT is kb+jwt.
	err = verifyTyp(holderJWT.Headers)
	if err != nil {
		return fmt.Errorf("failed to verify typ header: %w", err)
	}

	err = verifyJWT(holderJWT, pOpts.LeewayForClaimsValidation)
	if err != nil {
		return err
	}

	var bindingPayload keyBindingPayload

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &bindingPayload,
		TagName:          "json",
		Squash:           true,
		WeaklyTypedInput: true,
		DecodeHook:       utils.JSONNumberToJwtNumericDate(),
	})
	if err != nil {
		return fmt.Errorf("mapstruct verifyHodlder. error: %w", err)
	}

	if err = d.Decode(holderJWT.Payload); err != nil {
		return fmt.Errorf("mapstruct verifyHodlder decode. error: %w", err)
	}

	if pOpts.ExpectedNonceForHolderVerification != "" && pOpts.ExpectedNonceForHolderVerification != bindingPayload.Nonce {
		return fmt.Errorf("nonce value '%s' does not match expected nonce value '%s'",
			bindingPayload.Nonce, pOpts.ExpectedNonceForHolderVerification)
	}

	if pOpts.ExpectedAudienceForHolderVerification != "" && pOpts.ExpectedAudienceForHolderVerification != bindingPayload.Audience {
		return fmt.Errorf("audience value '%s' does not match expected audience value '%s'",
			bindingPayload.Audience, pOpts.ExpectedAudienceForHolderVerification)
	}

	return nil
}

func verifyTyp(joseHeaders jose.Headers) error {
	typ, ok := joseHeaders.Type()
	if !ok {
		return fmt.Errorf("missing typ")
	}

	if typ != "kb+jwt" {
		return fmt.Errorf("unexpected typ \"%s\"", typ)
	}

	return nil
}

// keyBindingPayload represents expected key binding payload.
type keyBindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}
