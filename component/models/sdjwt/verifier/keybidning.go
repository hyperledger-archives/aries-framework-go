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
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// verifyKeyBindingJWT verifies key binding JWT.
// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#section-6.2-4.6.1
func verifyKeyBindingJWT(holderJWT *afgjwt.JSONWebToken, pOpts *parseOpts) error {
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

	if pOpts.expectedAudienceForHolderVerification != "" &&
		pOpts.expectedAudienceForHolderVerification != bindingPayload.Audience {
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
