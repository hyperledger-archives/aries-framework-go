/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/square/go-jose/v3/jwt"
)

// MarshalJWS serializes JWT into signed form (JWS)
// todo refactor, do not pass privateKey (https://github.com/hyperledger/aries-framework-go/issues/339)
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, privateKey interface{}, keyID string) (string, error) { //nolint:lll
	return marshalJWS(jcc, signatureAlg, privateKey, keyID)
}

func unmarshalJWSClaims(rawJwt []byte, fetcher PublicKeyFetcher) (*JWTCredClaims, error) {
	parsedJwt, err := jwt.ParseSigned(string(rawJwt))
	if err != nil {
		return nil, fmt.Errorf("VC is not valid serialized JWS: %w", err)
	}

	credClaims := new(JWTCredClaims)
	err = parsedJwt.UnsafeClaimsWithoutVerification(credClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	err = verifyJWTSignature(parsedJwt, fetcher, credClaims.Issuer, credClaims)
	if err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	return credClaims, nil
}

func decodeCredJWS(rawJwt []byte, fetcher PublicKeyFetcher) ([]byte, error) {
	return decodeCredJWT(rawJwt, func(vcJWTBytes []byte) (*JWTCredClaims, error) {
		return unmarshalJWSClaims(rawJwt, fetcher)
	})
}
