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
	"time"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

// WithJWTDetachedPayload option is for definition of JWT detached payload.
func WithJWTDetachedPayload(payload []byte) common.ParseOpt {
	return common.WithJWTDetachedPayload(payload)
}

// WithSignatureVerifier option is for definition of signature verifier.
func WithSignatureVerifier(signatureVerifier jose.SignatureVerifier) common.ParseOpt {
	return common.WithSignatureVerifier(signatureVerifier)
}

// WithIssuerSigningAlgorithms option is for defining secure signing algorithms (for issuer).
func WithIssuerSigningAlgorithms(algorithms []string) common.ParseOpt {
	return common.WithIssuerSigningAlgorithms(algorithms)
}

// WithHolderSigningAlgorithms option is for defining secure signing algorithms (for holder).
func WithHolderSigningAlgorithms(algorithms []string) common.ParseOpt {
	return common.WithHolderSigningAlgorithms(algorithms)
}

// WithHolderBindingRequired option is for enforcing holder binding.
// Deprecated: use WithHolderVerificationRequired instead.
func WithHolderBindingRequired(flag bool) common.ParseOpt {
	return common.WithHolderVerificationRequired(flag)
}

// WithExpectedAudienceForHolderBinding option is to pass expected audience for holder binding.
// Deprecated: use WithExpectedAudienceForHolderVerification instead.
func WithExpectedAudienceForHolderBinding(audience string) common.ParseOpt {
	return common.WithExpectedAudienceForHolderVerification(audience)
}

// WithExpectedNonceForHolderBinding option is to pass nonce value for holder binding.
// Deprecated: use WithExpectedNonceForHolderVerification instead.
func WithExpectedNonceForHolderBinding(nonce string) common.ParseOpt {
	return common.WithExpectedNonceForHolderVerification(nonce)
}

// WithHolderVerificationRequired option is for enforcing holder verification.
func WithHolderVerificationRequired(flag bool) common.ParseOpt {
	return common.WithHolderVerificationRequired(flag)
}

// WithExpectedAudienceForHolderVerification option is to pass expected audience for holder binding.
func WithExpectedAudienceForHolderVerification(audience string) common.ParseOpt {
	return common.WithExpectedAudienceForHolderVerification(audience)
}

// WithExpectedNonceForHolderVerification option is to pass nonce value for holder binding.
func WithExpectedNonceForHolderVerification(nonce string) common.ParseOpt {
	return common.WithExpectedNonceForHolderVerification(nonce)
}

// WithLeewayForClaimsValidation is an option for claims time(s) validation.
func WithLeewayForClaimsValidation(duration time.Duration) common.ParseOpt {
	return common.WithLeewayForClaimsValidation(duration)
}

// Parse parses combined format for presentation and returns verified claims.
// The Verifier has to verify that all disclosed claim values were part of the original, Issuer-signed SD-JWT.
//
// At a high level, the Verifier:
//   - receives the Combined Format for Presentation from the Holder and verifies the signature of the SD-JWT using the
//     Issuer's public key,
//   - verifies the Holder (Key) Binding JWT, if Holder (Key) Binding is required by the Verifier's policy,
//     using the public key included in the SD-JWT,
//   - calculates the digests over the Holder-Selected Disclosures and verifies that each digest
//     is contained in the SD-JWT.
//
// Detailed algorithm:
// SDJWT V2 https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-02.html#name-verification-by-the-verifier
// SDJWT V5 https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-verification-by-the-verifie
//
// The Verifier will not, however, learn any claim values not disclosed in the Disclosures.
func Parse(combinedFormatForPresentation string, opts ...common.ParseOpt) (map[string]interface{}, error) {
	//// Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided)
	cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

	signedJWT, err := common.ValidateIssuerSignedSDJWT(cfp.SDJWT, cfp.Disclosures, opts...)
	if err != nil {
		return nil, fmt.Errorf("verifier ValidateIssuerSignedSDJWT: %w", err)
	}

	sdJWTVersion := common.ExtractSDJWTVersion(true, signedJWT.Headers)

	switch sdJWTVersion {
	case common.SDJWTVersionV5:
		return parseV5(cfp, signedJWT, opts...)
	default:
		return parseV2(cfp, signedJWT, opts...)
	}
}
