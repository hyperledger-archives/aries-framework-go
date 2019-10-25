/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/square/go-jose/v3/jwt"
)

// MarshalJWS serializes JWT presentation claims into signed form (JWS)
// todo refactor, do not pass privateKey (https://github.com/hyperledger/aries-framework-go/issues/339)
func (jpc *JWTPresClaims) MarshalJWS(signatureAlg JWSAlgorithm, privateKey interface{}, keyID string) (string, error) { //nolint:lll
	return marshalJWS(jpc, signatureAlg, privateKey, keyID)
}

func decodeVPFromJWS(vpJWTBytes []byte, fetcher PublicKeyFetcher) ([]byte, *rawPresentation, error) {
	return decodePresJWT(vpJWTBytes, func(vpJWTBytes []byte) (*JWTPresClaims, error) {
		return unmarshalPresJWSClaims(vpJWTBytes, fetcher)
	})
}

func unmarshalPresJWSClaims(jwtBytes []byte, fetcher PublicKeyFetcher) (claims *JWTPresClaims, e error) {
	parsedJwt, err := jwt.ParseSigned(string(jwtBytes))
	if err != nil {
		return nil, fmt.Errorf("VP is not valid serialized JWS: %w", err)
	}

	credClaims := new(JWTPresClaims)
	err = parsedJwt.UnsafeClaimsWithoutVerification(credClaims)
	if err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	err = verifyJWTSignature(parsedJwt, fetcher, credClaims.Issuer, credClaims)
	if err != nil {
		return nil, fmt.Errorf("JWT signature verification: %w", err)
	}

	return credClaims, nil
}
