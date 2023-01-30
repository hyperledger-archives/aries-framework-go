/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
)

// CombinedFormatSeparator is disclosure separator.
const (
	CombinedFormatSeparator = "~"

	SDAlgorithmKey = "_sd_alg"
	SDKey          = "_sd"
	CNFKey         = "cnf"

	disclosureParts = 3
	saltIndex       = 0
	nameIndex       = 1
	valueIndex      = 2
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
	SDJWT         string
	Disclosures   []string
	HolderBinding string
}

// Serialize will assemble combined format for presentation.
func (cf *CombinedFormatForPresentation) Serialize() string {
	presentation := cf.SDJWT
	for _, disclosure := range cf.Disclosures {
		presentation += CombinedFormatSeparator + disclosure
	}

	if len(cf.Disclosures) > 0 || cf.HolderBinding != "" {
		presentation += CombinedFormatSeparator
	}

	presentation += cf.HolderBinding

	return presentation
}

// DisclosureClaim defines claim.
type DisclosureClaim struct {
	Disclosure string
	Salt       string
	Name       string
	Value      interface{}
}

// GetDisclosureClaims de-codes disclosures.
func GetDisclosureClaims(disclosures []string) ([]*DisclosureClaim, error) {
	var claims []*DisclosureClaim

	for _, disclosure := range disclosures {
		claim, err := getDisclosureClaim(disclosure)
		if err != nil {
			return nil, err
		}

		claims = append(claims, claim)
	}

	return claims, nil
}

func getDisclosureClaim(disclosure string) (*DisclosureClaim, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	var disclosureArr []interface{}

	err = json.Unmarshal(decoded, &disclosureArr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure array: %w", err)
	}

	if len(disclosureArr) != disclosureParts {
		return nil, fmt.Errorf("disclosure array size[%d] must be %d", len(disclosureArr), disclosureParts)
	}

	salt, ok := disclosureArr[saltIndex].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt type[%T] must be string", disclosureArr[saltIndex])
	}

	name, ok := disclosureArr[nameIndex].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure name type[%T] must be string", disclosureArr[nameIndex])
	}

	claim := &DisclosureClaim{Disclosure: disclosure, Salt: salt, Name: name, Value: disclosureArr[valueIndex]}

	return claim, nil
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

	return &CombinedFormatForPresentation{SDJWT: sdJWT, Disclosures: disclosures, HolderBinding: holderBinding}
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
func VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error {
	var claims map[string]interface{}

	err := signedJWT.DecodeClaims(&claims)
	if err != nil {
		return err
	}

	// check that the _sd_alg claim is present
	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	for _, disclosure := range disclosures {
		digest, err := GetHash(cryptoHash, disclosure)
		if err != nil {
			return err
		}

		found, err := isDigestInClaims(digest, claims)
		if err != nil {
			return err
		}

		if !found {
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
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

	output := copyMap(claims)

	err = processDisclosedClaims(disclosureClaims, output, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosed claims: %w", err)
	}

	return output, nil
}

func processDisclosedClaims(disclosureClaims []*DisclosureClaim, claims map[string]interface{}, hash crypto.Hash) error { // nolint:lll
	digests, err := GetDisclosureDigests(claims)
	if err != nil {
		return err
	}

	for key, value := range claims {
		if obj, ok := value.(map[string]interface{}); ok {
			err := processDisclosedClaims(disclosureClaims, obj, hash)
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

		if _, ok := digests[digest]; ok {
			claims[dc.Name] = dc.Value
		}
	}

	delete(claims, SDKey)
	delete(claims, SDAlgorithmKey)

	return nil
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

// SliceToMap converts slice to map.
func SliceToMap(ids []string) map[string]bool {
	// convert slice to map
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	cm := make(map[string]interface{})

	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cm[k] = copyMap(vm)
		} else {
			cm[k] = v
		}
	}

	return cm
}
