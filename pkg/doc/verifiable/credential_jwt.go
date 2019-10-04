/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

// JWTCredClaims is JWT Claims extension by Verifiable Credential (with custom "vc" claim).
type JWTCredClaims struct {
	*jwt.Claims

	Credential *rawCredential `json:"vc,omitempty"`
}

// MarshalJWS serializes JWT into signed form (JWS)
func (vcc *JWTCredClaims) MarshalJWS(signatureAlg JWTAlgorithm, privateKey interface{}, keyID string) (string, error) { //nolint:lll
	key := jose.SigningKey{Algorithm: signatureAlg.Jose(), Key: privateKey}

	var signerOpts = &jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", keyID)

	signer, err := jose.NewSigner(key, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// create an instance of Builder that uses the signer
	builder := jwt.Signed(signer).Claims(vcc)

	// validate all ok, sign with the key, and return a compact JWT
	jws, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return jws, nil
}

// MarshalUnsecuredJWT serialized JWT into unsecured JWT.
func (vcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	headers := map[string]string{
		"alg": "none",
	}
	return marshalUnsecuredJWT(headers, vcc)
}

// jwtVCClaim is used to get content of "vc" claim of JWT.
type jwtVCClaim struct {
	VC map[string]interface{} `json:"vc,omitempty"`
}

func mergeRefinedVC(jsonCred map[string]interface{}, rawCred *rawCredential) error {
	rawData, err := json.Marshal(rawCred)
	if err != nil {
		return err
	}

	var rawMap map[string]interface{}

	err = json.Unmarshal(rawData, &rawMap)
	if err != nil {
		return err
	}

	// make the merge
	for k, v := range rawMap {
		jsonCred[k] = v
	}

	return nil
}

// credJWTDecoder parses JWT claims from serialized token into JWTCredClaims struct and JSON object.
// The implementation depends on the type of serialization, e.g. signed (JWT), unsecured (plain JWT).
type credJWTDecoder interface {
	UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error)
	UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error)
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

// credUnsecuredJWTDecoder parses serialized unsecured JWT.
type credUnsecuredJWTDecoder struct{}

func (ud *credUnsecuredJWTDecoder) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	_, bytesClaim, err := unmarshalUnsecuredJWT(rawJwt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode unsecured JWT")
	}

	credClaims := new(JWTCredClaims)
	err = json.Unmarshal(bytesClaim, credClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return credClaims, nil
}

func (ud *credUnsecuredJWTDecoder) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	_, bytesClaim, err := unmarshalUnsecuredJWT(rawJwt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode unsecured JWT")
	}

	rawClaims := new(jwtVCClaim)
	err = json.Unmarshal(bytesClaim, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return rawClaims.VC, nil
}

// decodeCredJWT parses JWT from the specified bytes array in compact format using jwtDecoder.
// It returns decoded Verifiable Credential refined by JWT Claims in raw byte array and rawCredential form.
func decodeCredJWT(rawJWT []byte, jwtDecoder credJWTDecoder) ([]byte, *rawCredential, error) {
	credClaims, err := jwtDecoder.UnmarshalClaims(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Verifiable Credential JWT claims: %w", err)
	}

	credJSON, err := jwtDecoder.UnmarshalVCClaim(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode raw Verifiable Credential JWT claims: %w", err)
	}

	// Apply VC-related claims from JWT.
	credClaims.refineCredFromJWTClaims()
	// Complement original "vc" JSON claim with data refined from JWT claims.
	if err = mergeRefinedVC(credJSON, credClaims.Credential); err != nil {
		return nil, nil, fmt.Errorf("failed to merge refined VC: %w", err)
	}

	var vcData []byte
	if vcData, err = json.Marshal(credJSON); err != nil {
		return nil, nil, errors.New("failed to marshal 'vc' claim of JWT")
	}

	return vcData, credClaims.Credential, nil
}

func (vcc *JWTCredClaims) refineCredFromJWTClaims() {
	raw := vcc.Credential

	if iss := vcc.Issuer; iss != "" {
		refineVCIssuerFromJWTClaims(raw, iss)
	}

	if nbf := vcc.NotBefore; nbf != nil {
		nbfTime := nbf.Time().UTC()
		raw.Issued = &nbfTime
	}

	if jti := vcc.ID; jti != "" {
		raw.ID = vcc.ID
	}

	if iat := vcc.IssuedAt; iat != nil {
		iatTime := iat.Time().UTC()
		raw.Issued = &iatTime
	}

	if exp := vcc.Expiry; exp != nil {
		expTime := exp.Time().UTC()
		raw.Expired = &expTime
	}
}

func decodeCredJWS(rawJwt []byte, fetcher PublicKeyFetcher) ([]byte, *rawCredential, error) {
	decoder := &credJWSDecoder{
		PKFetcher: fetcher,
	}
	return decodeCredJWT(rawJwt, decoder)
}

func decodeCredJWTUnsecured(rawJwt []byte) ([]byte, *rawCredential, error) {
	decoder := &credUnsecuredJWTDecoder{}
	return decodeCredJWT(rawJwt, decoder)
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

func refineVCIssuerFromJWTClaims(raw *rawCredential, iss string) {
	// Issuer of Verifiable Credential could be either string (id) or struct (with "id" field).
	switch issuer := raw.Issuer.(type) {
	case string:
		raw.Issuer = iss
	case map[string]interface{}:
		issuer["id"] = iss
	}
}
