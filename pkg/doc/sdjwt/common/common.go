/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"

	afgjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
)

// DisclosureSeparator is disclosure separator.
const DisclosureSeparator = "~"

// Payload represents SD-JWT payload.
type Payload struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	ID      string `json:"jti,omitempty"`

	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`

	SD    []string `json:"_sd,omitempty"`
	SDAlg string   `json:"_sd_alg,omitempty"`
}

// SDJWT holds SD-JWT info.
type SDJWT struct {
	JWTSerialized string
	Disclosures   []string
}

// ParseSDJWT parses SD-JWT serialized token into SDJWT parts.
func ParseSDJWT(sdJWTSerialized string) *SDJWT {
	parts := strings.Split(sdJWTSerialized, DisclosureSeparator)

	var disclosures []string
	if len(parts) > 1 {
		disclosures = parts[1:]
	}

	jwtSerialized := parts[0]

	return &SDJWT{JWTSerialized: jwtSerialized, Disclosures: disclosures}
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
	sdAlg, err := getSDAlg(claims)
	if err != nil {
		return err
	}

	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	cryptoHash, err := getCryptoHash(sdAlg)
	if err != nil {
		return err
	}

	claimsDisclosureDigests, err := getDisclosureDigests(claims)
	if err != nil {
		return err
	}

	for _, disclosure := range disclosures {
		digest, err := GetHash(cryptoHash, disclosure)
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
