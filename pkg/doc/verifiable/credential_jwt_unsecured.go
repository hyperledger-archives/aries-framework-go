/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
)

// MarshalUnsecuredJWT serialized JWT into unsecured JWT.
func (jcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	headers := map[string]string{
		"alg": "none",
	}
	return marshalUnsecuredJWT(headers, jcc)
}

// credUnsecuredJWTDecoder parses serialized unsecured JWT.
type credUnsecuredJWTDecoder struct{}

func (ud *credUnsecuredJWTDecoder) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	_, bytesClaim, err := unmarshalUnsecuredJWT(rawJwt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode unsecured JWT: %w", err)
	}

	credClaims := new(JWTCredClaims)
	err = json.Unmarshal(bytesClaim, credClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return credClaims, nil
}

func (ud *credUnsecuredJWTDecoder) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	_, bytesClaim, err := unmarshalUnsecuredJWT(rawJwt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode unsecured JWT: %w", err)
	}

	rawClaims := new(jwtVCClaim)
	err = json.Unmarshal(bytesClaim, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return rawClaims.VC, nil
}

func decodeCredJWTUnsecured(rawJwt []byte) ([]byte, *rawCredential, error) {
	decoder := new(credUnsecuredJWTDecoder)
	return decodeCredJWT(rawJwt, decoder)
}
