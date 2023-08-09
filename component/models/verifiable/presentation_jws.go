/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func (jpc *JWTPresClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	return marshalJWS(jpc, signatureAlg, signer, keyID)
}

func unmarshalPresJWSClaims(vpJWT string, checkProof bool, fetcher PublicKeyFetcher) (*JWTPresClaims, error) {
	var claims JWTPresClaims

	_, err := unmarshalJWS(vpJWT, checkProof, fetcher, &claims)
	if err != nil {
		return nil, err
	}

	return &claims, err
}

func decodeVPFromJWS(vpJWT string, checkProof bool, fetcher PublicKeyFetcher) ([]byte, *rawPresentation, error) {
	return decodePresJWT(vpJWT, func(vpJWT string) (*JWTPresClaims, error) {
		return unmarshalPresJWSClaims(vpJWT, checkProof, fetcher)
	})
}
