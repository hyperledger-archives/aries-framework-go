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

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

func parseV5(cfp *common.CombinedFormatForPresentation, signedJWT *afgjwt.JSONWebToken, pOpts *parseOpts) (map[string]interface{}, error) {
	// Check that the typ of the SD JWT is vc+sd-jwt.
	// Spec: https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-terbu-oauth-sd-jwt-vc.html#name-header-parameters
	err := common.VerifyTyp(signedJWT.Headers, "vc+sd-jwt")
	if err != nil {
		return nil, fmt.Errorf("failed to verify typ header: %w", err)
	}

	err = verifyKeyBinding(signedJWT, cfp.HolderVerification, pOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify key binding: %w", err)
	}

	return getDisclosedClaims(cfp.Disclosures, signedJWT, common.SDJWTVersionV5)
}

func verifyKeyBinding(sdJWT *afgjwt.JSONWebToken, keyBinding string, pOpts *parseOpts) error {
	if pOpts.holderVerificationRequired && keyBinding == "" {
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

func verifyKeyBindingJWT(holderJWT *afgjwt.JSONWebToken, pOpts *parseOpts) error {
	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err := common.VerifySigningAlg(holderJWT.Headers, pOpts.holderSigningAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to verify holder signing algorithm: %w", err)
	}

	// Check that the typ of the Key Binding JWT is kb+jwt.
	err = common.VerifyTyp(holderJWT.Headers, "kb+jwt")
	if err != nil {
		return fmt.Errorf("failed to verify typ header: %w", err)
	}

	err = common.VerifyJWT(holderJWT, pOpts.leewayForClaimsValidation)
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

	if pOpts.expectedNonceForHolderVerification != "" && pOpts.expectedNonceForHolderVerification != bindingPayload.Nonce {
		return fmt.Errorf("nonce value '%s' does not match expected nonce value '%s'",
			bindingPayload.Nonce, pOpts.expectedNonceForHolderVerification)
	}

	if pOpts.expectedAudienceForHolderVerification != "" && pOpts.expectedAudienceForHolderVerification != bindingPayload.Audience {
		return fmt.Errorf("audience value '%s' does not match expected audience value '%s'",
			bindingPayload.Audience, pOpts.expectedAudienceForHolderVerification)
	}

	return nil
}

// keyBindingPayload represents expected key binding payload.
type keyBindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}
