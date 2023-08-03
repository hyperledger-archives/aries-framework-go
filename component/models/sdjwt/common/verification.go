/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// VerifySigningAlg ensures that a signing algorithm was used that was deemed secure for the application.
// The none algorithm MUST NOT be accepted.
func VerifySigningAlg(joseHeaders jose.Headers, secureAlgs []string) error {
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

// VerifyJWT checks that the JWT is valid using nbf, iat, and exp claims (if provided in the JWT).
func VerifyJWT(signedJWT *afgjwt.JSONWebToken, leeway time.Duration) error {
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

// VerifyTyp checks JWT header parameters for the SD-JWT component.
func VerifyTyp(joseHeaders jose.Headers, expectedTyp string) error {
	typ, ok := joseHeaders.Type()
	if !ok {
		return fmt.Errorf("missing typ")
	}

	if typ != expectedTyp {
		return fmt.Errorf("unexpected typ \"%s\"", typ)
	}

	return nil
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(
	disclosures []string,
	signedJWT *afgjwt.JSONWebToken,
) error {
	claims := utils.CopyMap(signedJWT.Payload)
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	recData, err := getDisclosureClaimsInternal(
		disclosures,
		cryptoHash,
		false,
	)
	if err != nil {
		return err
	}

	_, err = parseDisclosureValue(claims, recData)
	if err != nil {
		return err
	}

	for _, claim := range recData.disclosures {
		if !slices.Contains(recData.nestedSD, claim.DisclosureDigest) {
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", claim.DisclosureDigest)
		}
	}

	return nil
}

func getDisclosureClaim(disclosure string, hash crypto.Hash) (*DisclosureClaim, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	var disclosureArr []interface{}

	err = json.Unmarshal(decoded, &disclosureArr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure array: %w", err)
	}

	if len(disclosureArr) < 2 {
		return nil, fmt.Errorf("disclosure array size[%d] must be greater %d", len(disclosureArr),
			2)
	}

	salt, ok := disclosureArr[0].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt type[%T] must be string", disclosureArr[1])
	}

	digest, err := GetHash(hash, disclosure)
	if err != nil {
		return nil, fmt.Errorf("get disclosure hash: %w", err)
	}

	claim := &DisclosureClaim{
		Digest:        digest,
		Disclosure:    disclosure,
		Salt:          salt,
		Version:       SDJWTVersionV2,
		IsValueParsed: false,
	}

	if len(disclosureArr) == 2 { // array
		claim.Value = disclosureArr[1]
		claim.Type = DisclosureClaimTypeArrayElement
		claim.Version = SDJWTVersionV5
	} else {
		name, ok := disclosureArr[1].(string)
		if !ok {
			return nil, fmt.Errorf("disclosure name type[%T] must be string", disclosureArr[1])
		}

		claim.Name = name
		claim.Value = disclosureArr[2]

		switch t := disclosureArr[2].(type) {
		case map[string]interface{}:
			claim.Type = DisclosureClaimTypeObject
			if KeyExistsInMap(SDKey, t) {
				claim.Version = SDJWTVersionV5
			}
		default:
			claim.Type = DisclosureClaimTypePlainText
		}
	}

	return claim, nil
}

func setDisclosureClaimValue(recData *recursiveData, disclosureClaim *DisclosureClaim) error {
	if disclosureClaim.IsValueParsed {
		return nil
	}

	newValue, err := parseDisclosureValue(disclosureClaim.Value, recData)
	if err != nil {
		return err
	}

	disclosureClaim.Value = newValue
	disclosureClaim.IsValueParsed = true

	return nil
}

// parseDisclosureValue returns new value of disclosure, resolving dependencies on other disclosures.
func parseDisclosureValue(dv interface{}, recData *recursiveData) (interface{}, error) {
	switch disclosureValue := dv.(type) {
	case []interface{}:
		var newValues []interface{}

		for _, value := range disclosureValue {
			parsedMap, ok := getMap(value)
			if !ok {
				// If it's not a map - use value as it is.
				newValues = append(newValues, value)
				continue
			}

			arrayElementDigestIface, ok := parsedMap[ArrayElementDigestKey]
			if !ok {
				return nil, errors.New("invalid array struct")
			}

			arrayElementDigest := fmt.Sprint(arrayElementDigestIface)
			if !slices.Contains(recData.nestedSD, arrayElementDigest) {
				recData.nestedSD = append(recData.nestedSD, arrayElementDigest)
			}

			disclosureDigestWrapper, ok := recData.disclosures[arrayElementDigest]
			if !ok {
				// If there is no disclosure provided for given array element digest - use map as it is.
				newValues = append(newValues, value)
				continue
			}

			// If disclosure is provided - parse the value.
			if err := setDisclosureClaimValue(recData, disclosureDigestWrapper); err != nil {
				return nil, err
			}

			// Use parsed disclosure value from prev strep.
			newValues = append(newValues, disclosureDigestWrapper.Value)
		}

		return newValues, nil
	case map[string]interface{}:
		newValues := make(map[string]interface{}, len(disclosureValue))

		// If there is nested digests.
		if nestedSDListIface, ok := disclosureValue[SDKey]; ok {
			nestedSDList, err := stringArray(nestedSDListIface)
			if err != nil {
				return nil, fmt.Errorf("get nested disclosure digests: %w", err)
			}

			var missingSDs []interface{}

			for _, digest := range nestedSDList {
				if !slices.Contains(recData.nestedSD, digest) {
					recData.nestedSD = append(recData.nestedSD, digest)
				}

				wrappedDisclosureClaim, ok := recData.disclosures[digest]
				if !ok {
					missingSDs = append(missingSDs, digest)
					continue
				}

				if err = setDisclosureClaimValue(recData, wrappedDisclosureClaim); err != nil {
					return nil, err
				}

				newValues[wrappedDisclosureClaim.Name] = wrappedDisclosureClaim.Value
			}

			if len(missingSDs) > 0 {
				newValues[SDKey] = missingSDs
			}
		}

		for k, disclosureNestedClaim := range disclosureValue {
			// This case was processed above.
			if k == SDKey {
				continue
			}

			newValue, err := parseDisclosureValue(disclosureNestedClaim, recData)
			if err != nil {
				return nil, fmt.Errorf("parse nested disclosure value")
			}

			newValues[k] = newValue
		}

		return newValues, nil
	default:
		return dv, nil
	}
}

func getDisclosureClaimsInternal(
	disclosures []string,
	hash crypto.Hash,
	modifyValues bool,
) (*recursiveData, error) {
	wrappedClaims := make(map[string]*DisclosureClaim, len(disclosures))

	for _, disclosure := range disclosures {
		claim, err := getDisclosureClaim(disclosure, hash)
		if err != nil {
			return nil, err
		}

		wrappedClaims[claim.Digest] = claim
	}

	recData := &recursiveData{
		disclosures: wrappedClaims,
	}

	for _, wrappedDisclosureClaim := range wrappedClaims {
		if err := setDisclosureClaimValue(recData, wrappedDisclosureClaim); err != nil {
			return nil, err
		}
	}

	return recData, nil
}
