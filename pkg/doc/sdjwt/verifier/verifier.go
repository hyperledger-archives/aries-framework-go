/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const confirmationClaim = "cnf"

// jwtParseOpts holds options for the SD-JWT parsing.
type parseOpts struct {
	detachedPayload []byte
	sigVerifier     jose.SignatureVerifier

	issuerSigningAlgorithms []string
	holderSigningAlgorithms []string

	holderBindingRequired            bool
	expectedAudienceForHolderBinding string
	expectedNonceForHolderBinding    string
}

// ParseOpt is the SD-JWT Parser option.
type ParseOpt func(opts *parseOpts)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *parseOpts) {
		opts.detachedPayload = payload
	}
}

// WithSignatureVerifier option is for definition of JWT detached payload.
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
func WithHolderBindingRequired(flag bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.holderBindingRequired = flag
	}
}

// WithExpectedAudienceForHolderBinding option is to pass expected audience for holder binding.
func WithExpectedAudienceForHolderBinding(audience string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedAudienceForHolderBinding = audience
	}
}

// WithExpectedNonceForHolderBinding option is to pass nonce value for holder binding.
func WithExpectedNonceForHolderBinding(nonce string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedNonceForHolderBinding = nonce
	}
}

// Parse parses combined format for presentation and returns verified claims.
func Parse(combinedFormatForPresentation string, opts ...ParseOpt) (map[string]interface{}, error) {
	defaultSigningAlgorithms := []string{"EdDSA", "RS256"}
	pOpts := &parseOpts{
		issuerSigningAlgorithms: defaultSigningAlgorithms,
		holderSigningAlgorithms: defaultSigningAlgorithms,
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	var jwtOpts []afgjwt.ParseOpt
	jwtOpts = append(jwtOpts,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))

	// Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided)
	cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

	// Validate the signature over the SD-JWT
	signedJWT, err := afgjwt.Parse(cfp.SDJWT, jwtOpts...)
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
	err = verifyJWT(signedJWT)
	if err != nil {
		return nil, err
	}

	// Check that there are no duplicate disclosures
	err = checkForDuplicates(cfp.Disclosures)
	if err != nil {
		return nil, fmt.Errorf("check disclosures: %w", err)
	}

	// Verify that all disclosures are present in SD-JWT.
	err = common.VerifyDisclosuresInSDJWT(cfp.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	err = verifyHolderBinding(signedJWT, cfp.HolderBinding, pOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify holder binding: %w", err)
	}

	return getVerifiedPayload(cfp.Disclosures, signedJWT)
}

func verifyHolderBinding(sdJWT *afgjwt.JSONWebToken, holderBinding string, pOpts *parseOpts) error {
	if pOpts.holderBindingRequired && holderBinding == "" {
		return fmt.Errorf("holder binding is required")
	}

	if holderBinding == "" {
		// not required and not present - nothing to do
		return nil
	}

	var claims map[string]interface{}

	err := sdJWT.DecodeClaims(&claims)
	if err != nil {
		return fmt.Errorf("failed to decode presentation claims: %w", err)
	}

	signatureVerifier, err := getSignatureVerifier(claims)
	if err != nil {
		return fmt.Errorf("failed to get signature verifier from presentation claims: %w", err)
	}

	holderJWT, err := afgjwt.Parse(holderBinding,
		afgjwt.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		return fmt.Errorf("failed to parse holder binding: %w", err)
	}

	err = verifyHolderJWT(holderJWT, pOpts)
	if err != nil {
		return fmt.Errorf("failed to verify holder JWT: %w", err)
	}

	return nil
}

func verifyHolderJWT(holderJWT *afgjwt.JSONWebToken, pOpts *parseOpts) error {
	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err := verifySigningAlg(holderJWT.Headers, pOpts.holderSigningAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to verify holder signing algorithm: %w", err)
	}

	err = verifyJWT(holderJWT)
	if err != nil {
		return err
	}

	var bindingPayload holderBindingPayload

	err = holderJWT.DecodeClaims(&bindingPayload)
	if err != nil {
		return fmt.Errorf("failed to decode holder claims: %w", err)
	}

	if pOpts.expectedNonceForHolderBinding != "" && pOpts.expectedNonceForHolderBinding != bindingPayload.Nonce {
		return fmt.Errorf("nonce value '%s' does not match expected nonce value '%s'",
			bindingPayload.Nonce, pOpts.expectedNonceForHolderBinding)
	}

	if pOpts.expectedAudienceForHolderBinding != "" && pOpts.expectedAudienceForHolderBinding != bindingPayload.Audience {
		return fmt.Errorf("audience value '%s' does not match expected audience value '%s'",
			bindingPayload.Audience, pOpts.expectedAudienceForHolderBinding)
	}

	return nil
}

func getSignatureVerifier(claims map[string]interface{}) (jose.SignatureVerifier, error) {
	cnf, err := getCNF(claims)
	if err != nil {
		return nil, err
	}

	signatureVerifier, err := getSignatureVerifierFromCNF(cnf)
	if err != nil {
		return nil, err
	}

	return signatureVerifier, nil
}

func getCNF(claims map[string]interface{}) (map[string]interface{}, error) {
	obj, ok := claims[confirmationClaim]
	if !ok {
		return nil, fmt.Errorf("%s must be present in SD-JWT", confirmationClaim)
	}

	cnf, ok := obj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", confirmationClaim)
	}

	return cnf, nil
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

func getVerifiedPayload(disclosures []string, signedJWT *afgjwt.JSONWebToken) (map[string]interface{}, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified claims: %w", err)
	}

	var claims map[string]interface{}

	err = signedJWT.DecodeClaims(&claims)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified claims: %w", err)
	}

	for _, dc := range disclosureClaims {
		claims[dc.Name] = dc.Value
	}

	delete(claims, common.SDKey)
	delete(claims, common.SDAlgorithmKey)

	return claims, nil
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
func verifyJWT(signedJWT *afgjwt.JSONWebToken) error {
	var claims jwt.Claims

	err := signedJWT.DecodeClaims(&claims)
	if err != nil {
		return err
	}

	// Validate checks claims in a token against expected values.
	// A default leeway value of one minute is used to compare time values.
	// It is validated using the expected.Time, or time.Now if not provided
	expected := jwt.Expected{}

	err = claims.Validate(expected)
	if err != nil {
		return fmt.Errorf("invalid JWT time values: %w", err)
	}

	return nil
}

// holderBindingPayload represents expected holder binding payload.
type holderBindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}
