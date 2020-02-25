/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
)

// MarshalUnsecuredJWT serialized JWT into unsecured JWT.
func (jcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	return marshalUnsecuredJWT(nil, jcc)
}

func unmarshalUnsecuredJWTClaims(rawJWT string) (*JWTCredClaims, error) {
	var claims JWTCredClaims

	err := unmarshalUnsecuredJWT(rawJWT, &claims)
	if err != nil {
		return nil, fmt.Errorf("parse VC in JWT Unsecured form: %w", err)
	}

	return &claims, nil
}

func decodeCredJWTUnsecured(rawJwt string) ([]byte, error) {
	return decodeCredJWT(rawJwt, unmarshalUnsecuredJWTClaims)
}
