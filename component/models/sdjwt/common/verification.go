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
	"time"

	"golang.org/x/exp/slices"

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

	parsedDisclosureClaims, err := getDisclosureClaims(disclosures, cryptoHash)
	if err != nil {
		return err
	}

	recData := &recursiveData{
		disclosures:          parsedDisclosureClaims,
		cleanupDigestsClaims: false,
	}

	_, err = discloseClaimValue(claims, recData)
	if err != nil {
		return err
	}

	// If the digest cannot be found in the SD-JWT payload, the Verifier MUST reject the Presentation.
	for _, disclosure := range parsedDisclosureClaims {
		if !disclosure.IsValueParsed {
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", disclosure.Digest)
		}
	}

	return nil
}

func setDisclosureClaimValue(recData *recursiveData, disclosureClaim *DisclosureClaim) error {
	if disclosureClaim.IsValueParsed {
		return nil
	}

	newValue, err := discloseClaimValue(disclosureClaim.Value, recData)
	if err != nil {
		return err
	}

	disclosureClaim.Value = newValue
	disclosureClaim.IsValueParsed = true

	return nil
}

// discloseClaimValue returns new value of claim, resolving dependencies on other disclosures.
func discloseClaimValue(claim interface{}, recData *recursiveData) (interface{}, error) { // nolint:funlen,gocyclo
	switch disclosureValue := claim.(type) {
	case []interface{}:
		var newValues []interface{}

		for _, value := range disclosureValue {
			parsedMap, ok := getMap(value)
			if !ok {
				// If it's not a map - use value as it is.
				newValues = append(newValues, value)
				continue
			}

			// Find all array elements that are objects with one key, that key being ... and referring to a string.
			arrayElementDigestIface, ok := parsedMap[ArrayElementDigestKey]
			if !ok {
				// If it's not a array element digest - object - use value as it is.
				newValues = append(newValues, value)
				continue
			}

			arrayElementDigest, ok := arrayElementDigestIface.(string)
			if !ok {
				return nil, errors.New("invalid array struct")
			}

			if slices.Contains(recData.nestedSD, arrayElementDigest) {
				// If any digests were found more than once in the previous step, the SD-JWT MUST be rejected.
				return nil, fmt.Errorf("digest '%s' has been included in more than one place", arrayElementDigest)
			}

			recData.nestedSD = append(recData.nestedSD, arrayElementDigest)

			disclosureClaim, ok := recData.disclosures[arrayElementDigest]
			if !ok {
				if recData.cleanupDigestsClaims {
					continue
				}
				// If there is no disclosure provided for given array element digest - use map as it is.
				newValues = append(newValues, value)

				continue
			}

			// If the digest was found in an array element:
			//   If the respective Disclosure is not a JSON-encoded array of two elements, the SD-JWT MUST be rejected.
			if disclosureClaim.Elements != disclosureElementsAmountForArrayDigest {
				return nil, fmt.Errorf("invald disclosure associated with array element digest %s", arrayElementDigest)
			}

			// If disclosure is provided - parse the value.
			if err := setDisclosureClaimValue(recData, disclosureClaim); err != nil {
				return nil, err
			}

			// Use parsed disclosure value from prev strep.
			newValues = append(newValues, disclosureClaim.Value)
		}

		if len(newValues) == 0 {
			return nil, nil
		}

		return newValues, nil
	case map[string]interface{}:
		newValues := make(map[string]interface{}, len(disclosureValue))

		// If there is nested digests.
		if nestedSDListIface, ok := disclosureValue[SDKey]; ok { // nolint:nestif
			nestedSDList, err := stringArray(nestedSDListIface)
			if err != nil {
				return nil, fmt.Errorf("get disclosure digests: %w", err)
			}

			var missingSDs []interface{}

			for _, digest := range nestedSDList {
				if slices.Contains(recData.nestedSD, digest) {
					// If any digests were found more than once in the previous step, the SD-JWT MUST be rejected.
					return nil, fmt.Errorf("digest '%s' has been included in more than one place", digest)
				}

				recData.nestedSD = append(recData.nestedSD, digest)

				disclosureClaim, ok := recData.disclosures[digest]
				if !ok {
					missingSDs = append(missingSDs, digest)
					continue
				}

				if disclosureClaim.Elements != disclosureElementsAmountForSDDigest {
					// If the digest was found in an object's _sd key:
					//  If the respective Disclosure is not a JSON-encoded array of three elements, the SD-JWT MUST be rejected.
					return nil, fmt.Errorf("invald disclosure associated with sd element digest %s", digest)
				}

				if err = setDisclosureClaimValue(recData, disclosureClaim); err != nil {
					return nil, err
				}

				// If the claim name already exists at the same level, the SD-JWT MUST be rejected.
				if _, ok = newValues[disclosureClaim.Name]; ok {
					return nil, fmt.Errorf("claim name '%s' already exists at the same level", disclosureClaim.Name)
				}

				newValues[disclosureClaim.Name] = disclosureClaim.Value
			}

			if !recData.cleanupDigestsClaims && len(missingSDs) > 0 {
				newValues[SDKey] = missingSDs
			}
		}

		for k, disclosureNestedClaim := range disclosureValue {
			if k == SDKey {
				continue
			}

			if k == SDAlgorithmKey && recData.cleanupDigestsClaims {
				continue
			}

			newValue, err := discloseClaimValue(disclosureNestedClaim, recData)
			if err != nil {
				return nil, err
			}

			// If the claim name already exists at the same level, the SD-JWT MUST be rejected.
			if _, ok := newValues[k]; ok {
				return nil, fmt.Errorf("claim name '%s' already exists at the same level", k)
			}

			if newValue != nil {
				newValues[k] = newValue
			}
		}

		return newValues, nil
	default:
		return claim, nil
	}
}

// getDisclosureClaims parses disclosures and returns map[string]*DisclosureClaim,
// where the key is disclosure digest calculated using provided hash.
func getDisclosureClaims(disclosures []string, hash crypto.Hash) (map[string]*DisclosureClaim, error) {
	wrappedClaims := make(map[string]*DisclosureClaim, len(disclosures))

	for _, disclosure := range disclosures {
		claim, err := getDisclosureClaim(disclosure, hash)
		if err != nil {
			return nil, err
		}

		wrappedClaims[claim.Digest] = claim
	}

	return wrappedClaims, nil
}

// getDisclosureClaim parses disclosure and returns *DisclosureClaim.
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

	if len(disclosureArr) < disclosureElementsAmountForArrayDigest {
		return nil, fmt.Errorf("disclosure array size[%d] must be greater %d", len(disclosureArr),
			2)
	}

	salt, ok := disclosureArr[saltPosition].(string)
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
		Elements:      len(disclosureArr),
	}

	switch len(disclosureArr) {
	case disclosureElementsAmountForArrayDigest: //array element
		enrichWithArrayElement(claim, disclosureArr)
	case disclosureElementsAmountForSDDigest:
		if err = enrichWithSDElement(claim, disclosureArr); err != nil {
			return nil, err
		}
	}

	return claim, nil
}

func enrichWithArrayElement(claim *DisclosureClaim, disclosureElementsArr []interface{}) {
	claim.Value = disclosureElementsArr[arrayDigestValuePosition]
	claim.Type = DisclosureClaimTypeArrayElement
	claim.Version = SDJWTVersionV5
}

func enrichWithSDElement(claim *DisclosureClaim, disclosureElementsArr []interface{}) error {
	name, ok := disclosureElementsArr[sdDigestNamePosition].(string)
	if !ok {
		return fmt.Errorf("disclosure name type[%T] must be string", disclosureElementsArr[1])
	}

	claim.Name = name
	claim.Value = disclosureElementsArr[sdDigestValuePosition]

	switch t := disclosureElementsArr[sdDigestValuePosition].(type) {
	case map[string]interface{}:
		claim.Type = DisclosureClaimTypeObject
		if KeyExistsInMap(SDKey, t) {
			claim.Version = SDJWTVersionV5
		}
	default:
		claim.Type = DisclosureClaimTypePlainText
	}

	return nil
}
