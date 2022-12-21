/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

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
	pOpts := &parseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	// TODO: Holder is not required to check issuer signature so we should probably have no-op verifier
	var jwtOpts []afgjwt.ParseOpt
	jwtOpts = append(jwtOpts,
		afgjwt.WithSignatureVerifier(pOpts.sigVerifier),
		afgjwt.WithJWTDetachedPayload(pOpts.detachedPayload))

	sdJWT := common.ParseSDJWT(sdJWTSerialized)

	err := VerifyDisclosuresInSDJWT(sdJWT.Disclosures, sdJWT.JWTSerialized, jwtOpts...)
	if err != nil {
		return nil, err
	}

	return sdJWT, nil
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(disclosures []string, jwtSerialized string, opts ...afgjwt.ParseOpt) error {
	signedJWT, err := afgjwt.Parse(jwtSerialized, opts...)
	if err != nil {
		return err
	}

	var claims map[string]interface{}

	err = signedJWT.DecodeClaims(&claims)
	if err != nil {
		return err
	}

	sdAlg, err := getSDAlg(claims)
	if err != nil {
		return err
	}

	cryptoHash, err := getCryptoHash(sdAlg)
	if err != nil {
		return err
	}

	claimsDisclosureDigests, err := getDisclosureDigests(claims)
	if err != nil {
		return err
	}

	for _, disclosure := range disclosures {
		digest, err := common.GetHash(cryptoHash, disclosure)
		if err != nil {
			return err
		}

		if _, ok := claimsDisclosureDigests[digest]; !ok {
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
}

func getCryptoHash(sdAlg string) (crypto.Hash, error) {
	var err error

	var cryptoHash crypto.Hash

	switch strings.ToUpper(sdAlg) {
	case crypto.SHA256.String():
		cryptoHash = crypto.SHA256
	default:
		err = fmt.Errorf("_sd_alg '%s 'not supported", sdAlg)
	}

	return cryptoHash, err
}

func getSDAlg(claims map[string]interface{}) (string, error) {
	obj, ok := claims["_sd_alg"]
	if !ok {
		return "", fmt.Errorf("_sd_alg must be present in SD-JWT")
	}

	str, ok := obj.(string)
	if !ok {
		return "", fmt.Errorf("_sd_alg must be a string")
	}

	return str, nil
}

func getDisclosureDigests(claims map[string]interface{}) (map[string]bool, error) {
	disclosuresObj, ok := claims["_sd"]
	if !ok {
		return nil, nil
	}

	disclosures, err := stringArray(disclosuresObj)
	if err != nil {
		return nil, fmt.Errorf("get disclosure digests: %w", err)
	}

	return sliceToMap(disclosures), nil
}

func stringArray(entry interface{}) ([]string, error) {
	if entry == nil {
		return nil, nil
	}

	entries, ok := entry.([]interface{})
	if !ok {
		return nil, fmt.Errorf("entry type[%T] is not an array", entry)
	}

	var result []string

	for _, e := range entries {
		if eStr, ok := e.(string); ok {
			result = append(result, eStr)
		} else {
			return nil, fmt.Errorf("entry item type[%T] is not a string", e)
		}
	}

	return result, nil
}

func sliceToMap(ids []string) map[string]bool {
	// convert slice to map
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}
