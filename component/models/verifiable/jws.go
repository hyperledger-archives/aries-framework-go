/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

// Signer defines signer interface which is used to sign VC JWT.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

// JwtSigner implement jose.Signer interface.
type JwtSigner struct {
	signer  Signer
	headers map[string]interface{}
}

// GetJWTSigner returns JWT Signer.
func GetJWTSigner(signer Signer, algorithm string) *JwtSigner {
	headers := map[string]interface{}{
		jose.HeaderAlgorithm: algorithm,
	}

	return &JwtSigner{signer: signer, headers: headers}
}

// Sign returns signature.
func (s JwtSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

// Headers returns headers.
func (s JwtSigner) Headers() jose.Headers {
	return s.headers
}

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}

// MarshalJWS serializes JWT presentation claims into signed form (JWS).
func marshalJWS(jwtClaims interface{}, signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	algName, err := signatureAlg.Name()
	if err != nil {
		return "", err
	}

	headers := map[string]interface{}{
		jose.HeaderKeyID: keyID,
	}

	token, err := jwt.NewSigned(jwtClaims, headers, GetJWTSigner(signer, algName))
	if err != nil {
		return "", err
	}

	return token.Serialize(false)
}

func unmarshalJWS(rawJwt string, checkProof bool, fetcher PublicKeyFetcher, claims interface{}) (jose.Headers, error) {
	var verifier jose.SignatureVerifier

	if checkProof {
		verifier = jwt.NewVerifier(jwt.KeyResolverFunc(fetcher))
	} else {
		verifier = &noVerifier{}
	}

	jsonWebToken, claimsRaw, err := jwt.Parse(rawJwt,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true),
	)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	err = json.Unmarshal(claimsRaw, claims)
	if err != nil {
		return nil, err
	}

	return jsonWebToken.Headers, nil
}
