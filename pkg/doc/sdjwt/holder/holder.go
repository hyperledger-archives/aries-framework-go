/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

const notFound = -1

// jwtParseOpts holds options for the SD-JWT parsing.
type parseOpts struct {
	detachedPayload []byte
	sigVerifier     jose.SignatureVerifier
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

// Parse parses input JWT in serialized form into JSON Web Token.
func Parse(sdJWTSerialized string, opts ...ParseOpt) (*common.SDJWT, error) {
	pOpts := &parseOpts{
		sigVerifier: &NoopSignatureVerifier{},
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	var jwtOpts []afgjwt.ParseOpt
	jwtOpts = append(jwtOpts,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))

	sdJWT := common.ParseSDJWT(sdJWTSerialized)

	signedJWT, err := afgjwt.Parse(sdJWT.JWTSerialized, jwtOpts...)
	if err != nil {
		return nil, err
	}

	err = common.VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	return sdJWT, nil
}

// DiscloseClaims discloses selected claims with specified claim names.
func DiscloseClaims(sdJWTSerialized string, claimNames []string) (string, error) {
	sdJWT := common.ParseSDJWT(sdJWTSerialized)

	if len(sdJWT.Disclosures) == 0 {
		return "", fmt.Errorf("no disclosures found in SD-JWT")
	}

	disclosures, err := common.GetDisclosureClaims(sdJWT.Disclosures)
	if err != nil {
		return "", err
	}

	var selectedDisclosures []string

	for _, claimName := range claimNames {
		if index := getDisclosureByClaimName(claimName, disclosures); index != notFound {
			selectedDisclosures = append(selectedDisclosures, sdJWT.Disclosures[index])
		}
	}

	combinedFormatForPresentation := sdJWT.JWTSerialized
	for _, disclosure := range selectedDisclosures {
		combinedFormatForPresentation += common.DisclosureSeparator + disclosure
	}

	return combinedFormatForPresentation, nil
}

func getDisclosureByClaimName(name string, disclosures []*common.DisclosureClaim) int {
	for index, disclosure := range disclosures {
		if disclosure.Name == name {
			return index
		}
	}

	return notFound
}

// NoopSignatureVerifier is no-op signature verifier (signature will not get checked).
type NoopSignatureVerifier struct {
}

// Verify implements signature verification.
func (sv *NoopSignatureVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}
