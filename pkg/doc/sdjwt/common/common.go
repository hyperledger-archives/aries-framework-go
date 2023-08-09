/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

// CombinedFormatSeparator is disclosure separator.
const (
	CombinedFormatSeparator = "~"

	SDAlgorithmKey = "_sd_alg"
	SDKey          = "_sd"
	CNFKey         = "cnf"
)

// CombinedFormatForIssuance holds SD-JWT and disclosures.
type CombinedFormatForIssuance = common.CombinedFormatForIssuance

// CombinedFormatForPresentation holds SD-JWT, disclosures and optional holder binding info.
type CombinedFormatForPresentation = common.CombinedFormatForPresentation

// DisclosureClaim defines claim.
type DisclosureClaim = common.DisclosureClaim

// GetDisclosureClaims de-codes disclosures.
func GetDisclosureClaims(disclosures []string, hash crypto.Hash) ([]*DisclosureClaim, error) {
	return common.GetDisclosureClaims(disclosures, hash)
}

// ParseCombinedFormatForIssuance parses combined format for issuance into CombinedFormatForIssuance parts.
func ParseCombinedFormatForIssuance(combinedFormatForIssuance string) *CombinedFormatForIssuance {
	return common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
}

// ParseCombinedFormatForPresentation parses combined format for presentation into CombinedFormatForPresentation parts.
func ParseCombinedFormatForPresentation(combinedFormatForPresentation string) *CombinedFormatForPresentation {
	return common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)
}

// GetHash calculates hash of data using hash function identified by hash.
func GetHash(hash crypto.Hash, value string) (string, error) {
	return common.GetHash(hash, value)
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error {
	return common.VerifyDisclosuresInSDJWT(disclosures, signedJWT)
}

// GetCryptoHashFromClaims returns crypto hash from claims.
func GetCryptoHashFromClaims(claims map[string]interface{}) (crypto.Hash, error) {
	return common.GetCryptoHashFromClaims(claims)
}

// GetCryptoHash returns crypto hash from SD algorithm.
func GetCryptoHash(sdAlg string) (crypto.Hash, error) {
	return common.GetCryptoHash(sdAlg)
}

// GetSDAlg returns SD algorithm from claims.
func GetSDAlg(claims map[string]interface{}) (string, error) {
	return common.GetSDAlg(claims)
}

// GetKeyFromVC returns key value from VC.
func GetKeyFromVC(key string, claims map[string]interface{}) (interface{}, bool) {
	return common.GetKeyFromVC(key, claims)
}

// GetCNF returns confirmation claim 'cnf'.
func GetCNF(claims map[string]interface{}) (map[string]interface{}, error) {
	return common.GetCNF(claims)
}

// GetDisclosureDigests returns digests from claims map.
func GetDisclosureDigests(claims map[string]interface{}) (map[string]bool, error) {
	return common.GetDisclosureDigests(claims)
}

// GetDisclosedClaims returns disclosed claims only.
func GetDisclosedClaims(disclosureClaims []*DisclosureClaim, claims map[string]interface{}) (map[string]interface{}, error) { // nolint:lll
	return common.GetDisclosedClaims(disclosureClaims, claims)
}

// SliceToMap converts slice to map.
func SliceToMap(ids []string) map[string]bool {
	return common.SliceToMap(ids)
}

// KeyExistsInMap checks if key exists in map.
func KeyExistsInMap(key string, m map[string]interface{}) bool {
	return common.KeyExistsInMap(key, m)
}
