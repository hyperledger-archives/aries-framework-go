/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential
type JWSAlgorithm int

const (
	// RS256 JWT Algorithm
	RS256 JWSAlgorithm = iota

	// EdDSA JWT Algorithm
	EdDSA

	// TODO support ES256K (https://github.com/square/go-jose/issues/263)
)

// Jose converts JWSAlgorithm to JOSE one.
func (ja JWSAlgorithm) Jose() jose.SignatureAlgorithm {
	switch ja {
	case RS256:
		return jose.RS256
	case EdDSA:
		return jose.EdDSA
	default:
		logger.Warnf("Unsupported algorithm: %v", ja)
		return jose.RS256
	}
}

// MarshalJWS serializes JWT into signed form (JWS)
func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, privateKey interface{}, keyID string) (string, error) { //nolint:lll
	key := jose.SigningKey{Algorithm: signatureAlg.Jose(), Key: privateKey}

	var signerOpts = &jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", keyID)

	signer, err := jose.NewSigner(key, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// create an instance of Builder that uses the signer
	builder := jwt.Signed(signer).Claims(jcc)

	// validate all ok, sign with the key, and return a compact JWT
	jws, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return jws, nil
}

// credJWSDecoder parses and verifies signature of serialized JWT. To verify the signature,
// Public Key Fetcher is used.
type credJWSDecoder struct {
	PKFetcher PublicKeyFetcher
}

func (jd *credJWSDecoder) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	parsedJwt, err := jwt.ParseSigned(string(rawJwt))
	if err != nil {
		return nil, fmt.Errorf("VC is not valid serialized JWS: %w", err)
	}

	credClaims := new(JWTCredClaims)
	err = parsedJwt.UnsafeClaimsWithoutVerification(credClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if verifyErr := verifyJWTSignature(parsedJwt, jd.PKFetcher, credClaims); verifyErr != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", verifyErr)
	}

	return credClaims, nil
}

func (jd *credJWSDecoder) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	parsedJwt, err := jwt.ParseSigned(string(rawJwt))
	if err != nil {
		return nil, fmt.Errorf("VC is not valid serialized JWS: %w", err)
	}

	jsonObjClaims := new(jwtVCClaim)
	err = parsedJwt.UnsafeClaimsWithoutVerification(jsonObjClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return jsonObjClaims.VC, nil
}

func verifyJWTSignature(parsedJwt *jwt.JSONWebToken, fetcher PublicKeyFetcher, credClaims *JWTCredClaims) error {
	var keyID string
	for _, h := range parsedJwt.Headers {
		if h.KeyID != "" {
			keyID = h.KeyID
			break
		}
	}
	publicKey, err := fetcher(credClaims.Issuer, keyID)
	if err != nil {
		return fmt.Errorf("failed to get public key for JWT signature verification: %w", err)
	}
	if err = parsedJwt.Claims(publicKey, credClaims); err != nil {
		return fmt.Errorf("JWT signature verification failed: %w", err)
	}
	return nil
}

func decodeCredJWS(rawJwt []byte, fetcher PublicKeyFetcher) ([]byte, *rawCredential, error) {
	decoder := &credJWSDecoder{
		PKFetcher: fetcher,
	}
	return decodeCredJWT(rawJwt, decoder)
}
