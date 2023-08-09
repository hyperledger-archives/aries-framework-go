/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
)

// MarshalJWS serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID)
}

func unmarshalJWSClaims(
	rawJwt string,
	checkProof bool,
	fetcher PublicKeyFetcher,
) (jose.Headers, *JWTCredClaims, error) {
	var claims JWTCredClaims

	joseHeaders, err := unmarshalJWS(rawJwt, checkProof, fetcher, &claims)
	if err != nil {
		return nil, nil, err
	}

	return joseHeaders, &claims, err
}

func decodeCredJWS(rawJwt string, checkProof bool, fetcher PublicKeyFetcher) (jose.Headers, []byte, error) {
	return decodeCredJWT(rawJwt, func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error) {
		return unmarshalJWSClaims(rawJwt, checkProof, fetcher)
	})
}
