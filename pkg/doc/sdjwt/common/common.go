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
