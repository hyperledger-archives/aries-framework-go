/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/trustbloc/kms-go/doc/jose"
)

// MarshalUnsecuredJWT serialized JWT into unsecured JWT.
func (jcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	return marshalUnsecuredJWT(nil, jcc)
}

func unmarshalUnsecuredJWTClaims(rawJWT string) (jose.Headers, *JWTCredClaims, error) {
	var claims JWTCredClaims

	hoseHeaders, err := unmarshalUnsecuredJWT(rawJWT, &claims)
	if err != nil {
		return nil, nil, fmt.Errorf("parse VC in JWT Unsecured form: %w", err)
	}

	return hoseHeaders, &claims, nil
}

func decodeCredJWTUnsecured(rawJwt string) ([]byte, error) {
	_, vcBytes, err := decodeCredJWT(rawJwt, unmarshalUnsecuredJWTClaims)

	return vcBytes, err
}
