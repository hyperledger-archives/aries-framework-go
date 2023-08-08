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
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"

	"github.com/go-jose/go-jose/v3/jwt"
)

// parseOpts holds options for the SD-JWT parsing.
type parseOpts struct {
	detachedPayload []byte
	sigVerifier     jose.SignatureVerifier

	issuerSigningAlgorithms []string
	holderSigningAlgorithms []string

	holderVerificationRequired            bool
	expectedAudienceForHolderVerification string
	expectedNonceForHolderVerification    string

	leewayForClaimsValidation time.Duration

	expectedTypHeader string
}

// ParseOpt is the SD-JWT Parser option.
type ParseOpt func(opts *parseOpts)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *parseOpts) {
		opts.detachedPayload = payload
	}
}

// WithSignatureVerifier option is for definition of signature verifier.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) ParseOpt {
	return func(opts *parseOpts) {
		opts.sigVerifier = signatureVerifier
	}
}

// WithIssuerSigningAlgorithms option is for defining secure signing algorithms (for issuer).
func WithIssuerSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *parseOpts) {
		opts.issuerSigningAlgorithms = algorithms
	}
}

// WithHolderSigningAlgorithms option is for defining secure signing algorithms (for holder).
func WithHolderSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *parseOpts) {
		opts.holderSigningAlgorithms = algorithms
	}
}

// WithHolderBindingRequired option is for enforcing holder binding.
// Deprecated: use WithHolderVerificationRequired instead.
func WithHolderBindingRequired(flag bool) ParseOpt {
	return WithHolderVerificationRequired(flag)
}

// WithExpectedAudienceForHolderBinding option is to pass expected audience for holder binding.
// Deprecated: use WithExpectedAudienceForHolderVerification instead.
func WithExpectedAudienceForHolderBinding(audience string) ParseOpt {
	return WithExpectedAudienceForHolderVerification(audience)
}

// WithExpectedNonceForHolderBinding option is to pass nonce value for holder binding.
// Deprecated: use WithExpectedNonceForHolderVerification instead.
func WithExpectedNonceForHolderBinding(nonce string) ParseOpt {
	return WithExpectedNonceForHolderVerification(nonce)
}

// WithHolderVerificationRequired option is for enforcing holder verification.
// For SDJWT V2 - this option defines Holder Binding verification as required.
// For SDJWT V5 - this option defines Key Binding verification as required.
func WithHolderVerificationRequired(flag bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.holderVerificationRequired = flag
	}
}

// WithExpectedAudienceForHolderVerification option is to pass expected audience for holder verification.
func WithExpectedAudienceForHolderVerification(audience string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedAudienceForHolderVerification = audience
	}
}

// WithExpectedNonceForHolderVerification option is to pass nonce value for holder verification.
func WithExpectedNonceForHolderVerification(nonce string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedNonceForHolderVerification = nonce
	}
}

// WithLeewayForClaimsValidation is an option for claims time(s) validation.
func WithLeewayForClaimsValidation(duration time.Duration) ParseOpt {
	return func(opts *parseOpts) {
		opts.leewayForClaimsValidation = duration
	}
}

// WithExpectedTypHeader is an option for JWT typ header validation.
// Might be relevant for SDJWT V5 VC validation.
// Spec: https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-terbu-oauth-sd-jwt-vc.html#name-header-parameters
func WithExpectedTypHeader(typ string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedTypHeader = typ
	}
}

// Parse parses combined format for presentation and returns verified claims.
// The Verifier has to verify that all disclosed claim values were part of the original, Issuer-signed SD-JWT.
//
// At a high level, the Verifier:
//   - receives the Combined Format for Presentation from the Holder and verifies the signature of the SD-JWT using the
//     Issuer's public key,
//   - verifies the Holder (Key) Binding JWT, if Holder Verification is required by the Verifier's policy,
//     using the public key included in the SD-JWT,
//   - calculates the digests over the Holder-Selected Disclosures and verifies that each digest
//     is contained in the SD-JWT.
//
// Detailed algorithm:
// nolint:lll
// V2 https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#name-verification-by-the-verifier
// V5 https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-verification-by-the-verifier
//
// The Verifier will not, however, learn any claim values not disclosed in the Disclosures.
func Parse(combinedFormatForPresentation string, opts ...ParseOpt) (map[string]interface{}, error) {
	defaultSigningAlgorithms := []string{"EdDSA", "RS256"}
	pOpts := &parseOpts{
		issuerSigningAlgorithms:   defaultSigningAlgorithms,
		holderSigningAlgorithms:   defaultSigningAlgorithms,
		leewayForClaimsValidation: jwt.DefaultLeeway,
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	// Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Verification JWT (if provided)
	cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

	signedJWT, err := validateIssuerSignedSDJWT(cfp.SDJWT, cfp.Disclosures, pOpts)
	if err != nil {
		return nil, err
	}

	// Verify that all disclosures are present in SD-JWT.
	err = common.VerifyDisclosuresInSDJWT(cfp.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	if pOpts.expectedTypHeader != "" {
		err = common.VerifyTyp(signedJWT.Headers, pOpts.expectedTypHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to verify typ header: %w", err)
		}
	}

	err = runHolderVerification(signedJWT, cfp.HolderVerification, pOpts)
	if err != nil {
		return nil, fmt.Errorf("run holder verification: %w", err)
	}

	cryptoHash, err := common.GetCryptoHashFromClaims(signedJWT.Payload)
	if err != nil {
		return nil, err
	}

	// Process the Disclosures.
	// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#section-6.2-4.5.1
	// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-3
	return getDisclosedClaims(cfp.Disclosures, signedJWT, cryptoHash)
}

func validateIssuerSignedSDJWT(sdjwt string, disclosures []string, pOpts *parseOpts) (*afgjwt.JSONWebToken, error) {
	// Validate the signature over the SD-JWT.
	signedJWT, _, err := afgjwt.Parse(sdjwt,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))
	if err != nil {
		return nil, err
	}

	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err = common.VerifySigningAlg(signedJWT.Headers, pOpts.issuerSigningAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to verify issuer signing algorithm: %w", err)
	}

	// TODO: Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.

	// Check that the SD-JWT is valid using nbf, iat, and exp claims,
	// if provided in the SD-JWT, and not selectively disclosed.
	err = common.VerifyJWT(signedJWT, pOpts.leewayForClaimsValidation)
	if err != nil {
		return nil, err
	}

	// Check that there are no duplicate disclosures
	err = checkForDuplicates(disclosures)
	if err != nil {
		return nil, fmt.Errorf("check disclosures: %w", err)
	}

	return signedJWT, nil
}

func checkForDuplicates(values []string) error {
	var duplicates []string

	valuesMap := make(map[string]bool)

	for _, val := range values {
		if _, ok := valuesMap[val]; !ok {
			valuesMap[val] = true
		} else {
			duplicates = append(duplicates, val)
		}
	}

	if len(duplicates) > 0 {
		return fmt.Errorf("duplicate values found %v", duplicates)
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
	hash crypto.Hash,
) (map[string]interface{}, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified payload: %w", err)
	}

	disclosedClaims, err := common.GetDisclosedClaims(disclosureClaims, utils.CopyMap(signedJWT.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	return disclosedClaims, nil
}

func runHolderVerification(sdJWT *afgjwt.JSONWebToken, holderVerificationJWT string, pOpts *parseOpts) error {
	if pOpts.holderVerificationRequired && holderVerificationJWT == "" {
		return fmt.Errorf("holder verification is required")
	}

	if holderVerificationJWT == "" {
		// not required and not present - nothing to do
		return nil
	}

	signatureVerifier, err := getSignatureVerifier(utils.CopyMap(sdJWT.Payload))
	if err != nil {
		return fmt.Errorf("failed to get signature verifier from presentation claims: %w", err)
	}

	// Validate the signature over the Key Binding JWT.
	holderJWT, _, err := afgjwt.Parse(holderVerificationJWT,
		afgjwt.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		return fmt.Errorf("parse holder verification JWT: %w", err)
	}

	err = verifyHolderVerificationJWT(holderJWT, pOpts)
	if err != nil {
		return fmt.Errorf("verify holder JWT: %w", err)
	}

	return nil
}

// verifyHolderVerificationJWT verifies Holder/Key Binding JWT.
func verifyHolderVerificationJWT(holderJWT *afgjwt.JSONWebToken, pOpts *parseOpts) error {
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

	sdJWTVersion := common.SDJWTVersionV2
	holderVerificationTyp, ok := holderJWT.Headers.Type()
	// Check that the typ of the Key Binding JWT is kb+jwt. If so - it's SD JWT V5.
	if ok && holderVerificationTyp == "kb+jwt" {
		sdJWTVersion = common.SDJWTVersionV5
	}

	switch sdJWTVersion {
	case common.SDJWTVersionV5:
		return verifyKeyBindingJWT(holderJWT, pOpts)
	default:
		return verifyHolderBindingJWT(holderJWT, pOpts)
	}
}
