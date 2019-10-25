/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
)

// MarshalUnsecuredJWT serializes JWT presentation claims into unsecured JWT.
func (jpc *JWTPresClaims) MarshalUnsecuredJWT() (string, error) { //nolint:lll
	headers := map[string]string{
		"alg": "none",
	}
	return marshalUnsecuredJWT(headers, jpc)
}

func decodeVPFromUnsecuredJWT(vpJWTBytes []byte) ([]byte, *rawPresentation, error) {
	return decodePresJWT(vpJWTBytes, func(vpJWTBytes []byte) (*JWTPresClaims, error) {
		_, bytesClaim, err := unmarshalUnsecuredJWT(vpJWTBytes)
		if err != nil {
			return nil, fmt.Errorf("decode unsecured JWT: %w", err)
		}

		vpClaims := new(JWTPresClaims)
		err = json.Unmarshal(bytesClaim, vpClaims)
		if err != nil {
			return nil, fmt.Errorf("parse JWT claims: %w", err)
		}

		return vpClaims, nil
	})
}
