/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// CombinedFormatSeparator is disclosure separator.
const (
	CombinedFormatSeparator = "~"

	SDAlgorithmKey = "_sd_alg"
	SDKey          = "_sd"
	CNFKey         = "cnf"
)

// SDJWTVersion represents version SD-JWT according to spec version.
type SDJWTVersion int

const (
	// SDJWTVersionDefault default SD-JWT version for compatibility purposes.
	SDJWTVersionDefault = SDJWTVersionV2
	SDJWTVersionV2      = SDJWTVersion(2)
	SDJWTVersionV5      = SDJWTVersion(5)
)

// CombinedFormatForIssuance holds SD-JWT and disclosures.
type CombinedFormatForIssuance struct {
	SDJWT       string
	Disclosures []string
}

// Serialize will assemble combined format for issuance.
func (cf *CombinedFormatForIssuance) Serialize() string {
	presentation := cf.SDJWT
	for _, disclosure := range cf.Disclosures {
		presentation += CombinedFormatSeparator + disclosure
	}

	return presentation
}

// CombinedFormatForPresentation holds SD-JWT, disclosures and optional holder binding info.
type CombinedFormatForPresentation struct {
	SDJWT       string
	Disclosures []string

	// Holder Verification JWT.
	// For SD JWT V2 field contains Holder Binding JWT data.
	// For SD JWT V5 field contains Key Binding JWT data.
	HolderVerification string
}

// Serialize will assemble combined format for presentation.
func (cf *CombinedFormatForPresentation) Serialize() string {
	presentation := cf.SDJWT
	for _, disclosure := range cf.Disclosures {
		presentation += CombinedFormatSeparator + disclosure
	}

	if len(cf.Disclosures) > 0 || cf.HolderVerification != "" {
		presentation += CombinedFormatSeparator
	}

	presentation += cf.HolderVerification

	return presentation
}

// DisclosureClaimType disclosure claim type, used for sd-jwt v5+.
type DisclosureClaimType int

const (
	// DisclosureClaimTypeUnknown default type for disclosure claim.
	DisclosureClaimTypeUnknown      = DisclosureClaimType(0)
	DisclosureClaimTypeArrayElement = DisclosureClaimType(1)
	DisclosureClaimTypeArray        = DisclosureClaimType(2)
)

// DisclosureClaim defines claim.
type DisclosureClaim struct {
	Disclosure string
	Salt       string
	Name       string
	Value      interface{}
	Type       DisclosureClaimType
}

// GetDisclosureClaims de-codes disclosures.
func GetDisclosureClaims(
	disclosures []string,
	version SDJWTVersion,
) ([]*DisclosureClaim, error) {
	instance := newCommon(version)

	return instance.GetDisclosureClaims(disclosures)
}

// ParseCombinedFormatForIssuance parses combined format for issuance into CombinedFormatForIssuance parts.
func ParseCombinedFormatForIssuance(combinedFormatForIssuance string) *CombinedFormatForIssuance {
	parts := strings.Split(combinedFormatForIssuance, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 1 {
		disclosures = parts[1:]
	}

	sdJWT := parts[0]

	return &CombinedFormatForIssuance{SDJWT: sdJWT, Disclosures: disclosures}
}

// ParseCombinedFormatForPresentation parses combined format for presentation into CombinedFormatForPresentation parts.
func ParseCombinedFormatForPresentation(combinedFormatForPresentation string) *CombinedFormatForPresentation {
	parts := strings.Split(combinedFormatForPresentation, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 2 {
		disclosures = parts[1 : len(parts)-1]
	}

	var holderBinding string
	if len(parts) > 1 {
		holderBinding = parts[len(parts)-1]
	}

	sdJWT := parts[0]

	return &CombinedFormatForPresentation{SDJWT: sdJWT, Disclosures: disclosures, HolderVerification: holderBinding}
}

// GetHash calculates hash of data using hash function identified by hash.
func GetHash(hash crypto.Hash, value string) (string, error) {
	if !hash.Available() {
		return "", fmt.Errorf("hash function not available for: %d", hash)
	}

	h := hash.New()

	if _, hashErr := h.Write([]byte(value)); hashErr != nil {
		return "", hashErr
	}

	result := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(result), nil
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(
	disclosures []string,
	signedJWT *afgjwt.JSONWebToken,
	version SDJWTVersion,
) error {
	return newCommon(version).VerifyDisclosuresInSDJWT(disclosures, signedJWT)
}

func isDigestInClaims(digest string, claims map[string]interface{}) (bool, error) {
	var found bool

	digests, err := GetDisclosureDigests(claims)
	if err != nil {
		return false, err
	}

	for _, value := range claims {
		if obj, ok := value.(map[string]interface{}); ok {
			found, err = isDigestInClaims(digest, obj)
			if err != nil {
				return false, err
			}

			if found {
				return found, nil
			}
		}
	}

	_, ok := digests[digest]

	return ok, nil
}

// GetCryptoHashFromClaims returns crypto hash from claims.
func GetCryptoHashFromClaims(claims map[string]interface{}) (crypto.Hash, error) {
	var cryptoHash crypto.Hash

	// check that the _sd_alg claim is present
	sdAlg, err := GetSDAlg(claims)
	if err != nil {
		return cryptoHash, err
	}

	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	return GetCryptoHash(sdAlg)
}

// GetCryptoHash returns crypto hash from SD algorithm.
func GetCryptoHash(sdAlg string) (crypto.Hash, error) {
	var err error

	var cryptoHash crypto.Hash

	// From spec: the hash algorithms MD2, MD4, MD5, RIPEMD-160, and SHA-1 revealed fundamental weaknesses
	// and they MUST NOT be used.

	switch strings.ToUpper(sdAlg) {
	case crypto.SHA256.String():
		cryptoHash = crypto.SHA256
	case crypto.SHA384.String():
		cryptoHash = crypto.SHA384
	case crypto.SHA512.String():
		cryptoHash = crypto.SHA512
	default:
		err = fmt.Errorf("%s '%s' not supported", SDAlgorithmKey, sdAlg)
	}

	return cryptoHash, err
}

// GetSDAlg returns SD algorithm from claims.
func GetSDAlg(claims map[string]interface{}) (string, error) {
	var alg string

	obj, ok := claims[SDAlgorithmKey]
	if !ok {
		// if claims contain 'vc' claim it may be present in vc
		obj, ok = GetKeyFromVC(SDAlgorithmKey, claims)
		if !ok {
			return "", fmt.Errorf("%s must be present in SD-JWT", SDAlgorithmKey)
		}
	}

	alg, ok = obj.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", SDAlgorithmKey)
	}

	return alg, nil
}

// GetKeyFromVC returns key value from VC.
func GetKeyFromVC(key string, claims map[string]interface{}) (interface{}, bool) {
	if obj, ok := claims[key]; ok {
		return obj, true
	}

	vcObj, ok := claims["vc"]
	if !ok {
		return nil, false
	}

	vc, ok := vcObj.(map[string]interface{})
	if !ok {
		return nil, false
	}

	obj, ok := vc[key]
	if !ok {
		return nil, false
	}

	return obj, true
}

// GetCNF returns confirmation claim 'cnf'.
func GetCNF(claims map[string]interface{}) (map[string]interface{}, error) {
	obj, ok := claims[CNFKey]
	if !ok {
		obj, ok = GetKeyFromVC(CNFKey, claims)
		if !ok {
			return nil, fmt.Errorf("%s must be present in SD-JWT", CNFKey)
		}
	}

	cnf, ok := obj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", CNFKey)
	}

	return cnf, nil
}

// GetDisclosureDigests returns digests from claims map.
func GetDisclosureDigests(claims map[string]interface{}) (map[string]bool, error) {
	disclosuresObj, ok := claims[SDKey]
	if !ok {
		return nil, nil
	}

	disclosures, err := stringArray(disclosuresObj)
	if err != nil {
		return nil, fmt.Errorf("get disclosure digests: %w", err)
	}

	return SliceToMap(disclosures), nil
}

// GetDisclosedClaims returns disclosed claims only.
func GetDisclosedClaims(disclosureClaims []*DisclosureClaim, claims map[string]interface{}) (map[string]interface{}, error) { // nolint:lll
	hash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto hash from claims: %w", err)
	}

	output := utils.CopyMap(claims)
	includedDigests := make(map[string]bool)

	err = processDisclosedClaims(disclosureClaims, output, includedDigests, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosed claims: %w", err)
	}

	return output, nil
}

func processDisclosedClaims(disclosureClaims []*DisclosureClaim, claims map[string]interface{}, includedDigests map[string]bool, hash crypto.Hash) error { // nolint:lll
	digests, err := GetDisclosureDigests(claims)
	if err != nil {
		return err
	}

	for key, value := range claims {
		if obj, ok := value.(map[string]interface{}); ok {
			err := processDisclosedClaims(disclosureClaims, obj, includedDigests, hash)
			if err != nil {
				return err
			}

			claims[key] = obj
		}
	}

	for _, dc := range disclosureClaims {
		digest, err := GetHash(hash, dc.Disclosure)
		if err != nil {
			return err
		}

		if _, ok := digests[digest]; !ok {
			continue
		}

		_, digestAlreadyIncluded := includedDigests[digest]
		if digestAlreadyIncluded {
			// If there is more than one place where the digest is included,
			// the Verifier MUST reject the Presentation.
			return fmt.Errorf("digest '%s' has been included in more than one place", digest)
		}

		err = validateClaim(dc, claims)
		if err != nil {
			return err
		}

		claims[dc.Name] = dc.Value

		includedDigests[digest] = true
	}

	delete(claims, SDKey)
	delete(claims, SDAlgorithmKey)

	return nil
}

func validateClaim(dc *DisclosureClaim, claims map[string]interface{}) error {
	_, claimNameExists := claims[dc.Name]
	if claimNameExists {
		// If the claim name already exists at the same level, the Verifier MUST reject the Presentation.
		return fmt.Errorf("claim name '%s' already exists at the same level", dc.Name)
	}

	m, ok := getMap(dc.Value)
	if ok {
		if KeyExistsInMap(SDKey, m) {
			// If the claim value contains an object with an _sd key (at the top level or nested deeper),
			// the Verifier MUST reject the Presentation.
			return fmt.Errorf("claim value contains an object with an '%s' key", SDKey)
		}
	}

	return nil
}

func getMap(value interface{}) (map[string]interface{}, bool) {
	val, ok := value.(map[string]interface{})

	return val, ok
}

func stringArray(entry interface{}) ([]string, error) {
	if entry == nil {
		return nil, nil
	}

	sliceValue := reflect.ValueOf(entry)
	if sliceValue.Kind() != reflect.Slice {
		return nil, fmt.Errorf("entry type[%T] is not an array", entry)
	}

	// Iterate over the slice and convert each element to a string
	stringSlice := make([]string, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		sliceVal := sliceValue.Index(i).Interface()
		val, ok := sliceVal.(string)

		if !ok {
			return nil, fmt.Errorf("entry item type[%T] is not a string", sliceVal)
		}

		stringSlice[i] = val
	}

	return stringSlice, nil
}

// SliceToMap converts slice to map.
func SliceToMap(ids []string) map[string]bool {
	// convert slice to map
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}

// KeyExistsInMap checks if key exists in map.
func KeyExistsInMap(key string, m map[string]interface{}) bool {
	for k, v := range m {
		if k == key {
			return true
		}

		if obj, ok := v.(map[string]interface{}); ok {
			exists := KeyExistsInMap(key, obj)
			if exists {
				return true
			}
		}
	}

	return false
}

// ExtractSDJWTVersion returns version of SD-JWT (SDJWTVersion).
func ExtractSDJWTVersion(isSDJWT bool, joseHeaders jose.Headers) SDJWTVersion {
	if !isSDJWT {
		return 0
	}

	typ, _ := joseHeaders.Type()

	switch typ {
	case "vc+sd-jwt":
		return SDJWTVersionV5
	default:
		return SDJWTVersionDefault
	}
}
