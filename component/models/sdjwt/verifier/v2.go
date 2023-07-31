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
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

func parseV2(
	cfp *common.CombinedFormatForPresentation,
	signedJWT *afgjwt.JSONWebToken,
	pOpts *parseOpts,
) (map[string]interface{}, error) {
	err := verifyHolderBinding(signedJWT, cfp.HolderVerification, pOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify holder binding: %w", err)
	}

	// Process the Disclosures.
	// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#section-6.2-4.5.1
	return getDisclosedClaims(cfp.Disclosures, signedJWT, common.SDJWTVersionV2)
}

func verifyHolderBinding(sdJWT *afgjwt.JSONWebToken, holderBinding string, pOpts *parseOpts) error {
	if pOpts.holderVerificationRequired && holderBinding == "" {
		return fmt.Errorf("holder binding is required")
	}

	if holderBinding == "" {
		// not required and not present - nothing to do
		return nil
	}

	signatureVerifier, err := getSignatureVerifier(utils.CopyMap(sdJWT.Payload))
	if err != nil {
		return fmt.Errorf("failed to get signature verifier from presentation claims: %w", err)
	}

	holderJWT, _, err := afgjwt.Parse(holderBinding,
		afgjwt.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		return fmt.Errorf("failed to parse holder binding: %w", err)
	}

	err = verifyHolderBindingJWT(holderJWT, pOpts)
	if err != nil {
		return fmt.Errorf("failed to verify holder JWT: %w", err)
	}

	return nil
}

func verifyHolderBindingJWT(holderJWT *afgjwt.JSONWebToken, pOpts *parseOpts) error {
	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err := common.VerifySigningAlg(holderJWT.Headers, pOpts.holderSigningAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to verify holder signing algorithm: %w", err)
	}

	err = common.VerifyJWT(holderJWT, pOpts.leewayForClaimsValidation)
	if err != nil {
		return err
	}

	var bindingPayload holderBindingPayload

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

func getSignatureVerifier(claims map[string]interface{}) (jose.SignatureVerifier, error) {
	cnf, err := common.GetCNF(claims)
	if err != nil {
		return nil, err
	}

	signatureVerifier, err := getSignatureVerifierFromCNF(cnf)
	if err != nil {
		return nil, err
	}

	return signatureVerifier, nil
}

// getSignatureVerifierFromCNF will evolve over time as we support more cnf modes and algorithms.
func getSignatureVerifierFromCNF(cnf map[string]interface{}) (jose.SignatureVerifier, error) {
	jwkObj, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwk must be present in cnf")
	}

	// TODO: Add handling other methods: "jwe", "jku" and "kid"

	jwkObjBytes, err := json.Marshal(jwkObj)
	if err != nil {
		return nil, fmt.Errorf("marshal jwk: %w", err)
	}

	j := jwk.JWK{}

	err = j.UnmarshalJSON(jwkObjBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal jwk: %w", err)
	}

	signatureVerifier, err := afgjwt.GetVerifier(&verifier.PublicKey{JWK: &j})
	if err != nil {
		return nil, fmt.Errorf("get verifier from jwk: %w", err)
	}

	return signatureVerifier, nil
}

func getDisclosedClaims(
	disclosures []string,
	signedJWT *afgjwt.JSONWebToken,
	version common.SDJWTVersion,
) (map[string]interface{}, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures, version)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified payload: %w", err)
	}

	disclosedClaims, err := common.GetDisclosedClaims(disclosureClaims, utils.CopyMap(signedJWT.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	return disclosedClaims, nil
}

// holderBindingPayload represents expected holder binding payload.
type holderBindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}
