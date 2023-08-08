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
	"time"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/verifier"
)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) verifier.ParseOpt {
	return verifier.WithJWTDetachedPayload(payload)
}

// WithSignatureVerifier option is for definition of signature verifier.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) verifier.ParseOpt {
	return verifier.WithSignatureVerifier(signatureVerifier)
}

// WithIssuerSigningAlgorithms option is for defining secure signing algorithms (for issuer).
func WithIssuerSigningAlgorithms(algorithms []string) verifier.ParseOpt {
	return verifier.WithIssuerSigningAlgorithms(algorithms)
}

// WithHolderSigningAlgorithms option is for defining secure signing algorithms (for holder).
func WithHolderSigningAlgorithms(algorithms []string) verifier.ParseOpt {
	return verifier.WithHolderSigningAlgorithms(algorithms)
}

// WithHolderBindingRequired option is for enforcing holder binding.
// Deprecated: use WithHolderVerificationRequired instead.
func WithHolderBindingRequired(flag bool) verifier.ParseOpt {
	return WithHolderVerificationRequired(flag)
}

// WithExpectedAudienceForHolderBinding option is to pass expected audience for holder binding.
// Deprecated: use WithExpectedAudienceForHolderVerification instead.
func WithExpectedAudienceForHolderBinding(audience string) verifier.ParseOpt {
	return WithExpectedAudienceForHolderVerification(audience)
}

// WithExpectedNonceForHolderBinding option is to pass nonce value for holder binding.
// Deprecated: use WithExpectedNonceForHolderVerification instead.
func WithExpectedNonceForHolderBinding(nonce string) verifier.ParseOpt {
	return WithExpectedNonceForHolderVerification(nonce)
}

// WithHolderVerificationRequired option is for enforcing holder verification.
// For SDJWT V2 - this option defines Holder Binding verification as required.
// For SDJWT V5 - this option defines Key Binding verification as required.
func WithHolderVerificationRequired(flag bool) verifier.ParseOpt {
	return verifier.WithHolderVerificationRequired(flag)
}

// WithExpectedAudienceForHolderVerification option is to pass expected audience for holder verification.
func WithExpectedAudienceForHolderVerification(audience string) verifier.ParseOpt {
	return verifier.WithExpectedAudienceForHolderVerification(audience)
}

// WithExpectedNonceForHolderVerification option is to pass nonce value for holder verification.
func WithExpectedNonceForHolderVerification(nonce string) verifier.ParseOpt {
	return verifier.WithExpectedNonceForHolderVerification(nonce)
}

// WithLeewayForClaimsValidation is an option for claims time(s) validation.
func WithLeewayForClaimsValidation(duration time.Duration) verifier.ParseOpt {
	return verifier.WithLeewayForClaimsValidation(duration)
}

// WithExpectedTypHeader is an option for JWT typ header validation.
// Might be relevant for SDJWT V5 VC validation.
// Spec: https://vcstuff.github.io/draft-terbu-sd-jwt-vc/draft-terbu-oauth-sd-jwt-vc.html#name-header-parameters
func WithExpectedTypHeader(typ string) verifier.ParseOpt {
	return verifier.WithExpectedTypHeader(typ)
}

// Parse parses combined format for presentation and returns verified claims.
// The Verifier has to verify that all disclosed claim values were part of the original, Issuer-signed SD-JWT.
//
// At a high level, the Verifier:
//   - receives the Combined Format for Presentation from the Holder and verifies the signature of the SD-JWT using the
//     Issuer's public key,
//   - verifies the Holder Binding JWT, if Holder Binding is required by the Verifier's policy,
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
func Parse(combinedFormatForPresentation string, opts ...verifier.ParseOpt) (map[string]interface{}, error) {
	return verifier.Parse(combinedFormatForPresentation, opts...)
}
