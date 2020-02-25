/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
)

// Signer defines signer interface which is used to sign VC JWT.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

// jwtSigner implement jose.Signer interface
type jwtSigner struct {
	signer  Signer
	headers map[string]interface{}
}

func getJWTSigner(signer Signer, algorithm string) *jwtSigner {
	headers := map[string]interface{}{
		jose.HeaderAlgorithm: algorithm,
		jose.HeaderType:      jwt.TypeJWT,
	}

	return &jwtSigner{signer: signer, headers: headers}
}

func (s jwtSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

func (s jwtSigner) Headers() jose.Headers {
	return s.headers
}

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct {
}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}

// MarshalJWS serializes JWT presentation claims into signed form (JWS)
func marshalJWS(jwtClaims interface{}, signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	algName, err := signatureAlg.name()
	if err != nil {
		return "", err
	}

	headers := map[string]interface{}{
		jose.HeaderKeyID: keyID,
	}

	token, err := jwt.NewSigned(jwtClaims, headers, getJWTSigner(signer, algName))
	if err != nil {
		return "", err
	}

	return token.Serialize(false)
}

func unmarshalJWS(rawJwt string, checkProof bool, fetcher PublicKeyFetcher, claims interface{}) error {
	var verifier jose.SignatureVerifier

	if checkProof {
		verifier = jwt.NewVerifier(jwt.KeyResolverFunc(fetcher))
	} else {
		verifier = &noVerifier{}
	}

	jsonWebToken, err := jwt.Parse(rawJwt, jwt.WithSignatureVerifier(verifier))
	if err != nil {
		return fmt.Errorf("parse JWT: %w", err)
	}

	err = jsonWebToken.DecodeClaims(claims)
	if err != nil {
		return err
	}

	return nil
}
