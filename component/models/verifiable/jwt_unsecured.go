/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

func marshalUnsecuredJWT(headers jose.Headers, claims interface{}) (string, error) {
	token, err := jwt.NewUnsecured(claims, headers)
	if err != nil {
		return "", fmt.Errorf("marshal unsecured JWT: %w", err)
	}

	return token.Serialize(false)
}

func unmarshalUnsecuredJWT(rawJWT string, claims interface{}) (jose.Headers, error) {
	token, _, err := jwt.Parse(rawJWT, jwt.WithSignatureVerifier(jwt.UnsecuredJWTVerifier()))
	if err != nil {
		return nil, fmt.Errorf("unmarshal unsecured JWT: %w", err)
	}

	return token.Headers, token.DecodeClaims(claims)
}
