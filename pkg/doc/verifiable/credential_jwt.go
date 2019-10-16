/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/square/go-jose/v3/jwt"
)

// JWTCredClaims is JWT Claims extension by Verifiable Credential (with custom "vc" claim).
type JWTCredClaims struct {
	*jwt.Claims

	Credential *rawCredential `json:"vc,omitempty"`
}

// newJWTCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newJWTCredClaims(vc *Credential, minimizeVc bool) (*JWTCredClaims, error) {
	subjectID, err := vc.SubjectID()
	if err != nil {
		return nil, fmt.Errorf("failed to get VC subject id: %w", err)
	}

	// currently jwt encoding supports only single subject (by the spec)
	jwtClaims := &jwt.Claims{
		Issuer:    vc.Issuer.ID,                   // iss
		NotBefore: jwt.NewNumericDate(*vc.Issued), // nbf
		ID:        vc.ID,                          // jti
		Subject:   subjectID,                      // sub
		IssuedAt:  jwt.NewNumericDate(*vc.Issued), // iat (not in spec, follow the interop project approach)
	}
	if vc.Expired != nil {
		jwtClaims.Expiry = jwt.NewNumericDate(*vc.Expired) // exp
	}

	var raw *rawCredential
	if minimizeVc {
		vcCopy := *vc
		vcCopy.Expired = nil
		vcCopy.Issuer.ID = ""
		vcCopy.Issued = nil
		vcCopy.ID = ""
		raw = vcCopy.raw()
	} else {
		raw = vc.raw()
	}

	credClaims := &JWTCredClaims{
		Claims:     jwtClaims,
		Credential: raw,
	}

	return credClaims, nil
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

// jwtCredClaimsDecoder parses JWT claims from serialized token into JWTCredClaims struct and JSON object.
// The implementation depends on the type of serialization, e.g. signed (JWT), unsecured (plain JWT).
type jwtCredClaimsDecoder interface {
	UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error)
	UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error)
}

// decodeCredJWT parses JWT from the specified bytes array in compact format using jwtDecoder.
// It returns decoded Verifiable Credential refined by JWT Claims in raw byte array and rawCredential form.
func decodeCredJWT(rawJWT []byte, credClaimsDecoder jwtCredClaimsDecoder) ([]byte, *rawCredential, error) {
	credClaims, err := credClaimsDecoder.UnmarshalClaims(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Verifiable Credential JWT claims: %w", err)
	}

	credJSON, err := credClaimsDecoder.UnmarshalVCClaim(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode raw Verifiable Credential JWT claims: %w", err)
	}

	// Apply VC-related claims from JWT.
	credClaims.refineFromJWTClaims()
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

func (jcc *JWTCredClaims) refineFromJWTClaims() {
	raw := jcc.Credential

	if iss := jcc.Issuer; iss != "" {
		refineVCIssuerFromJWTClaims(raw, iss)
	}

	if nbf := jcc.NotBefore; nbf != nil {
		nbfTime := nbf.Time().UTC()
		raw.Issued = &nbfTime
	}

	if jti := jcc.ID; jti != "" {
		raw.ID = jti
	}

	if iat := jcc.IssuedAt; iat != nil {
		iatTime := iat.Time().UTC()
		raw.Issued = &iatTime
	}

	if exp := jcc.Expiry; exp != nil {
		expTime := exp.Time().UTC()
		raw.Expired = &expTime
	}
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
