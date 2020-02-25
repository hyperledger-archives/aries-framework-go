/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
)

// MarshalUnsecuredJWT serializes JWT presentation claims into unsecured JWT.
func (jpc *JWTPresClaims) MarshalUnsecuredJWT() (string, error) {
	return marshalUnsecuredJWT(nil, jpc)
}

func unmarshalUnsecuredJWTPresClaims(vpJWT string) (*JWTPresClaims, error) {
	var claims JWTPresClaims

	err := unmarshalUnsecuredJWT(vpJWT, &claims)
	if err != nil {
		return nil, fmt.Errorf("parse VP in JWT Unsecured form: %w", err)
	}

	return &claims, nil
}

func decodeVPFromUnsecuredJWT(vpJWT string) ([]byte, *rawPresentation, error) {
	return decodePresJWT(vpJWT, unmarshalUnsecuredJWTPresClaims)
}
