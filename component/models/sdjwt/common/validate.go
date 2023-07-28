/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// ParseOpts holds options for the SD-JWT parsing.
type ParseOpts struct {
	DetachedPayload []byte
	sigVerifier     jose.SignatureVerifier

	issuerSigningAlgorithms []string
	HolderSigningAlgorithms []string

	HolderVerificationRequired            bool
	ExpectedAudienceForHolderVerification string
	ExpectedNonceForHolderVerification    string

	LeewayForClaimsValidation time.Duration
}

// ParseOpt is the SD-JWT Parser option.
type ParseOpt func(opts *ParseOpts)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *ParseOpts) {
		opts.DetachedPayload = payload
	}
}

// WithSignatureVerifier option is for definition of signature verifier.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) ParseOpt {
	return func(opts *ParseOpts) {
		opts.sigVerifier = signatureVerifier
	}
}

// WithIssuerSigningAlgorithms option is for defining secure signing algorithms (for issuer).
func WithIssuerSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *ParseOpts) {
		opts.issuerSigningAlgorithms = algorithms
	}
}

// WithHolderSigningAlgorithms option is for defining secure signing algorithms (for holder).
func WithHolderSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *ParseOpts) {
		opts.HolderSigningAlgorithms = algorithms
	}
}

// WithHolderVerificationRequired option is for enforcing holder verification.
// For SDJWT V2 - this option defines Holder Binding verification as required.
// For SDJWT V5 - this option defines Key Binding verification as required.
func WithHolderVerificationRequired(flag bool) ParseOpt {
	return func(opts *ParseOpts) {
		opts.HolderVerificationRequired = flag
	}
}

// WithExpectedAudienceForHolderVerification option is to pass expected audience for holder verification.
func WithExpectedAudienceForHolderVerification(audience string) ParseOpt {
	return func(opts *ParseOpts) {
		opts.ExpectedAudienceForHolderVerification = audience
	}
}

// WithExpectedNonceForHolderVerification option is to pass nonce value for holder verification.
func WithExpectedNonceForHolderVerification(nonce string) ParseOpt {
	return func(opts *ParseOpts) {
		opts.ExpectedNonceForHolderVerification = nonce
	}
}

// WithLeewayForClaimsValidation is an option for claims time(s) validation.
func WithLeewayForClaimsValidation(duration time.Duration) ParseOpt {
	return func(opts *ParseOpts) {
		opts.LeewayForClaimsValidation = duration
	}
}

// ValidateIssuerSignedSDJWT validates SDJWT signature.
// It's a common function used for validating SDJWT V2 and SDJWT V5.
//
// Detailed algorithm:
// V2: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#section-6.2-4.3.1
// V5: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-4.2.1
func ValidateIssuerSignedSDJWT(sdjwt string, disclosures []string, opts ...ParseOpt) (*afgjwt.JSONWebToken, error) {
	defaultSigningAlgorithms := []string{"EdDSA", "RS256"}
	pOpts := &ParseOpts{
		issuerSigningAlgorithms:   defaultSigningAlgorithms,
		LeewayForClaimsValidation: jwt.DefaultLeeway,
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	var jwtOpts []afgjwt.ParseOpt
	jwtOpts = append(jwtOpts,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.DetachedPayload))

	// Validate the signature over the SD-JWT
	signedJWT, _, err := afgjwt.Parse(sdjwt, jwtOpts...)
	if err != nil {
		return nil, err
	}

	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err = verifySigningAlg(signedJWT.Headers, pOpts.issuerSigningAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to verify issuer signing algorithm: %w", err)
	}

	// TODO: Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.

	// Check that the SD-JWT is valid using nbf, iat, and exp claims,
	// if provided in the SD-JWT, and not selectively disclosed.
	err = verifyJWT(signedJWT, pOpts.LeewayForClaimsValidation)
	if err != nil {
		return nil, err
	}

	// Check that there are no duplicate disclosures
	err = checkForDuplicates(disclosures)
	if err != nil {
		return nil, fmt.Errorf("check disclosures: %w", err)
	}

	sdJWTVersion := ExtractSDJWTVersion(true, signedJWT.Headers)

	// Verify that all disclosures are present in SD-JWT.
	// Check that the _sd_alg claim is present and its value is understood and the hash algorithm is deemed secure.
	err = VerifyDisclosuresInSDJWT(disclosures, signedJWT, sdJWTVersion)
	if err != nil {
		return nil, err
	}

	return signedJWT, nil
}

func verifySigningAlg(joseHeaders jose.Headers, secureAlgs []string) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return fmt.Errorf("missing alg")
	}

	if alg == afgjwt.AlgorithmNone {
		return fmt.Errorf("alg value cannot be 'none'")
	}

	if !contains(secureAlgs, alg) {
		return fmt.Errorf("alg '%s' is not in the allowed list", alg)
	}

	return nil
}

func contains(values []string, val string) bool {
	for _, v := range values {
		if v == val {
			return true
		}
	}

	return false
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

// verifyJWT checks that the JWT is valid using nbf, iat, and exp claims (if provided in the JWT).
func verifyJWT(signedJWT *afgjwt.JSONWebToken, leeway time.Duration) error {
	var claims jwt.Claims

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &claims,
		TagName:          "json",
		Squash:           true,
		WeaklyTypedInput: true,
		DecodeHook:       utils.JSONNumberToJwtNumericDate(),
	})
	if err != nil {
		return fmt.Errorf("mapstruct verifyJWT. error: %w", err)
	}

	if err = d.Decode(signedJWT.Payload); err != nil {
		return fmt.Errorf("mapstruct verifyJWT decode. error: %w", err)
	}

	// Validate checks claims in a token against expected values.
	// It is validated using the expected.Time, or time.Now if not provided
	expected := jwt.Expected{}

	err = claims.ValidateWithLeeway(expected, leeway)
	if err != nil {
		return fmt.Errorf("invalid JWT time values: %w", err)
	}

	return nil
}
