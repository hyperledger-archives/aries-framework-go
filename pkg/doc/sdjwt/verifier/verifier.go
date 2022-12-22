/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"fmt"

	"github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

// jwtParseOpts holds options for the SD-JWT parsing.
type parseOpts struct {
	detachedPayload   []byte
	sigVerifier       jose.SignatureVerifier
	signingAlgorithms []string
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

// WithSigningAlgorithms option is for defining secure signing algorithms.
func WithSigningAlgorithms(algorithms []string) ParseOpt {
	return func(opts *parseOpts) {
		opts.signingAlgorithms = algorithms
	}
}

// Parse parses input JWT in serialized form into JSON Web Token.
func Parse(sdJWTSerialized string, opts ...ParseOpt) (*common.SDJWT, error) {
	pOpts := &parseOpts{
		signingAlgorithms: []string{"EdDSA", "RS256"},
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	var jwtOpts []afgjwt.ParseOpt
	jwtOpts = append(jwtOpts,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))

	// Separate the Presentation into the SD-JWT, the Disclosures (if any), and the Holder Binding JWT (if provided)
	sdJWT := common.ParseSDJWT(sdJWTSerialized)

	// Validate the signature over the SD-JWT
	signedJWT, err := afgjwt.Parse(sdJWT.JWTSerialized, jwtOpts...)
	if err != nil {
		return nil, err
	}

	// Ensure that a signing algorithm was used that was deemed secure for the application.
	// The none algorithm MUST NOT be accepted.
	err = verifySigningAlg(signedJWT.Headers, pOpts.signingAlgorithms)
	if err != nil {
		return nil, err
	}

	// TODO: Validate the Issuer of the SD-JWT and that the signing key belongs to this Issuer.

	// Check that the SD-JWT is valid using nbf, iat, and exp claims,
	// if provided in the SD-JWT, and not selectively disclosed.
	err = verifySDJWT(signedJWT)
	if err != nil {
		return nil, err
	}

	// Check that there are no duplicate disclosures
	err = checkForDuplicates(sdJWT.Disclosures)
	if err != nil {
		return nil, fmt.Errorf("check disclosures: %w", err)
	}

	// Verify that all disclosures are present in SD-JWT.
	err = common.VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	return sdJWT, nil
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

// verifySDJWT checks that the SD-JWT is valid using nbf, iat, and exp claims (if provided in the SD-JWT).
func verifySDJWT(signedJWT *afgjwt.JSONWebToken) error {
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
		return fmt.Errorf("failed to validate SD-JWT time values: %w", err)
	}

	return nil
}
