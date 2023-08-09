/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package holder enables the Holder: an entity that receives SD-JWTs from the Issuer and has control over them.
package holder

import (
	"crypto"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

// Claim defines claim.
type Claim struct {
	Disclosure string
	Name       string
	Value      interface{}
}

// jwtParseOpts holds options for the SD-JWT parsing.
type parseOpts struct {
	detachedPayload []byte
	sigVerifier     jose.SignatureVerifier

	issuerSigningAlgorithms []string
	sdjwtV5Validation       bool
	expectedTypHeader       string

	leewayForClaimsValidation time.Duration
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

// WithSDJWTV5Validation option is for defining additional holder verification defined in SDJWT V5 spec.
// Section: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-3
func WithSDJWTV5Validation(flag bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.sdjwtV5Validation = flag
	}
}

// WithIssuerSigningAlgorithms option is for defining secure signing algorithms (for holder verification).
func WithIssuerSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *parseOpts) {
		opts.issuerSigningAlgorithms = algorithms
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

// Parse parses issuer SD-JWT and returns claims that can be selected.
// The Holder MUST perform the following (or equivalent) steps when receiving a Combined Format for Issuance:
//
//   - Separate the SD-JWT and the Disclosures in the Combined Format for Issuance.
//
//   - Hash all the Disclosures separately.
//
//   - Find the places in the SD-JWT where the digests of the Disclosures are included.
//
//   - If any of the digests cannot be found in the SD-JWT, the Holder MUST reject the SD-JWT.
//
//   - Decode Disclosures and obtain plaintext of the claim values.
//
//     It is up to the Holder how to maintain the mapping between the Disclosures and the plaintext claim values to
//     be able to display them to the End-User when needed.
func Parse(combinedFormatForIssuance string, opts ...ParseOpt) ([]*Claim, error) {
	pOpts := &parseOpts{
		sigVerifier: &NoopSignatureVerifier{},
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	// Validate the signature over the Issuer-signed JWT.
	signedJWT, _, err := afgjwt.Parse(cfi.SDJWT,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))
	if err != nil {
		return nil, err
	}

	if pOpts.sdjwtV5Validation {
		// Apply additional validation for V5.
		if err = applySDJWTV5Validation(signedJWT, cfi.Disclosures, pOpts); err != nil {
			return nil, err
		}
	}

	err = common.VerifyDisclosuresInSDJWT(cfi.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	cryptoHash, err := common.GetCryptoHashFromClaims(signedJWT.Payload)
	if err != nil {
		return nil, err
	}

	return getClaims(cfi.Disclosures, cryptoHash)
}

func getClaims(
	disclosures []string,
	hash crypto.Hash,
) ([]*Claim, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get claims from disclosures: %w", err)
	}

	var claims []*Claim
	for _, disclosure := range disclosureClaims {
		claims = append(claims,
			&Claim{
				Disclosure: disclosure.Disclosure,
				Name:       disclosure.Name,
				Value:      disclosure.Value,
			})
	}

	return claims, nil
}

// applySDJWTV5Validation applies additional validation to signedJWT that were introduces in V5 spec.
// Doc: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#section-6.1-3.
func applySDJWTV5Validation(signedJWT *afgjwt.JSONWebToken, disclosures []string, pOpts *parseOpts) error {
	// If a Key Binding JWT is received by a Holder, the SD-JWT SHOULD be rejected.
	var possibleKeyBinding string
	if l := len(disclosures); l > 0 {
		possibleKeyBinding = disclosures[l-1]
	}

	if afgjwt.IsJWS(possibleKeyBinding) || afgjwt.IsJWTUnsecured(possibleKeyBinding) {
		return fmt.Errorf("unexpected key binding JWT supplied")
	}

	if pOpts.expectedTypHeader != "" {
		// Check that the typ header.
		// Spec: https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-terbu-oauth-sd-jwt-vc.html#name-header-parameters
		err := common.VerifyTyp(signedJWT.Headers, pOpts.expectedTypHeader)
		if err != nil {
			return fmt.Errorf("verify typ header: %w", err)
		}
	}

	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err := common.VerifySigningAlg(signedJWT.Headers, pOpts.issuerSigningAlgorithms)
	if err != nil {
		return fmt.Errorf("failed to verify issuer signing algorithm: %w", err)
	}

	// TODO: Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.

	// Check that the SD-JWT is valid using nbf, iat, and exp claims,
	// if provided in the SD-JWT, and not selectively disclosed.
	err = common.VerifyJWT(signedJWT, pOpts.leewayForClaimsValidation)
	if err != nil {
		return err
	}

	return nil
}

// BindingPayload represents holder verification payload.
type BindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}

// BindingInfo defines holder verification payload and signer.
type BindingInfo struct {
	Payload BindingPayload
	Signer  jose.Signer
	Headers jose.Headers
}

// options holds options for holder.
type options struct {
	holderVerificationInfo *BindingInfo
}

// Option is a holder option.
type Option func(opts *options)

// WithHolderBinding option to set optional holder binding.
// Deprecated. Use WithHolderVerification instead.
func WithHolderBinding(info *BindingInfo) Option {
	return func(opts *options) {
		opts.holderVerificationInfo = info
	}
}

// WithHolderVerification option to set optional holder verification.
func WithHolderVerification(info *BindingInfo) Option {
	return func(opts *options) {
		opts.holderVerificationInfo = info
	}
}

// CreatePresentation is a convenience method to assemble combined format for presentation
// using selected disclosures (claimsToDisclose) and optional holder verification.
// This call assumes that combinedFormatForIssuance has already been parsed and verified using Parse() function.
//
// For presentation to a Verifier, the Holder MUST perform the following (or equivalent) steps:
//   - Decide which Disclosures to release to the Verifier, obtaining proper End-User consent if necessary.
//   - If Holder Binding is required, create a Holder Binding JWT.
//   - Create the Combined Format for Presentation from selected Disclosures and Holder Verification JWT(if applicable).
//   - Send the Presentation to the Verifier.
func CreatePresentation(combinedFormatForIssuance string, claimsToDisclose []string, opts ...Option) (string, error) {
	hOpts := &options{}

	for _, opt := range opts {
		opt(hOpts)
	}

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	if len(cfi.Disclosures) == 0 {
		return "", fmt.Errorf("no disclosures found in SD-JWT")
	}

	disclosuresMap := common.SliceToMap(cfi.Disclosures)

	for _, ctd := range claimsToDisclose {
		if _, ok := disclosuresMap[ctd]; !ok {
			return "", fmt.Errorf("disclosure '%s' not found in SD-JWT", ctd)
		}
	}

	var err error

	var hbJWT string

	if hOpts.holderVerificationInfo != nil {
		hbJWT, err = CreateHolderVerification(hOpts.holderVerificationInfo)
		if err != nil {
			return "", fmt.Errorf("failed to create holder verification: %w", err)
		}
	}

	cf := common.CombinedFormatForPresentation{
		SDJWT:              cfi.SDJWT,
		Disclosures:        claimsToDisclose,
		HolderVerification: hbJWT,
	}

	return cf.Serialize(), nil
}

// CreateHolderVerification will create holder verification from binding info.
func CreateHolderVerification(info *BindingInfo) (string, error) {
	hbJWT, err := afgjwt.NewSigned(info.Payload, info.Headers, info.Signer)
	if err != nil {
		return "", err
	}

	return hbJWT.Serialize(false)
}

// NoopSignatureVerifier is no-op signature verifier (signature will not get checked).
type NoopSignatureVerifier struct {
}

// Verify implements signature verification.
func (sv *NoopSignatureVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}
