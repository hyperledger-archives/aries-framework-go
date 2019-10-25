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

func unmarshalUnsecuredJWTClaims(rawJwt []byte) (*JWTCredClaims, error) {
	_, bytesClaim, err := unmarshalUnsecuredJWT(rawJwt)
	if err != nil {
		return nil, fmt.Errorf("decode unsecured JWT: %w", err)
	}

	credClaims := new(JWTCredClaims)
	err = json.Unmarshal(bytesClaim, credClaims)
	if err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	return credClaims, nil
}

func decodeCredJWTUnsecured(rawJwt []byte) ([]byte, error) {
	return decodeCredJWT(rawJwt, unmarshalUnsecuredJWTClaims)
}
