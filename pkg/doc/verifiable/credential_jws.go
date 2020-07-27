/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// MarshalJWS serializes JWT into signed form (JWS).
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID)
}

func unmarshalJWSClaims(rawJwt string, checkProof bool, fetcher PublicKeyFetcher) (*JWTCredClaims, error) {
	var claims JWTCredClaims

	err := unmarshalJWS(rawJwt, checkProof, fetcher, &claims)
	if err != nil {
		return nil, err
	}

	return &claims, err
}

func decodeCredJWS(rawJwt string, checkProof bool, fetcher PublicKeyFetcher) ([]byte, error) {
	return decodeCredJWT(rawJwt, func(vcJWTBytes string) (*JWTCredClaims, error) {
		return unmarshalJWSClaims(rawJwt, checkProof, fetcher)
	})
}
