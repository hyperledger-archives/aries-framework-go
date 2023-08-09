/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
)

const (
	vcIssuanceDateField   = "issuanceDate"
	vcIDField             = "id"
	vcExpirationDateField = "expirationDate"
	vcIssuerField         = "issuer"
	vcIssuerIDField       = "id"
)

// JWTCredClaims is JWT Claims extension by Verifiable Credential (with custom "vc" claim).
type JWTCredClaims struct {
	*jwt.Claims

	VC map[string]interface{} `json:"vc,omitempty"`
}

// ToSDJWTV5CredentialPayload defines custom marshalling of JWTCredClaims.
// Key difference with default marshaller is that returned object does not contain custom "vc" root claim.
// Example:
//
//	https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-example-4b-w3c-verifiable-c.
func (jcc *JWTCredClaims) ToSDJWTV5CredentialPayload() ([]byte, error) {
	type Alias JWTCredClaims

	alias := Alias(*jcc)

	vcMap := alias.VC

	alias.VC = nil

	data, err := jsonutil.MarshalWithCustomFields(alias, vcMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWTW3CCredClaims: %w", err)
	}

	return data, nil
}

// UnmarshalJSON defines custom unmarshalling of JWTCredClaims from JSON.
// For SD-JWT case, it supports both v2 and v5 formats.
func (jcc *JWTCredClaims) UnmarshalJSON(data []byte) error {
	type Alias JWTCredClaims

	alias := (*Alias)(jcc)

	customFields := make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, customFields)
	if err != nil {
		return fmt.Errorf("unmarshal JWTCredClaims: %w", err)
	}

	if len(customFields) > 0 && len(alias.VC) == 0 {
		alias.VC = customFields
	}

	return nil
}

// newJWTCredClaims creates JWT Claims of VC with an option to minimize certain fields of VC
// which is put into "vc" claim.
func newJWTCredClaims(vc *Credential, minimizeVC bool) (*JWTCredClaims, error) {
	subjectID, err := SubjectID(vc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	// currently jwt encoding supports only single subject (by the spec)
	jwtClaims := &jwt.Claims{
		Issuer:    vc.Issuer.ID,                           // iss
		NotBefore: josejwt.NewNumericDate(vc.Issued.Time), // nbf
		ID:        vc.ID,                                  // jti
		Subject:   subjectID,                              // sub
	}

	if vc.Expired != nil {
		jwtClaims.Expiry = josejwt.NewNumericDate(vc.Expired.Time) // exp
	}

	if vc.Issued != nil {
		jwtClaims.IssuedAt = josejwt.NewNumericDate(vc.Issued.Time)
	}

	var raw *rawCredential

	if minimizeVC {
		vcCopy := *vc
		vcCopy.Expired = nil
		vcCopy.Issuer.ID = ""
		vcCopy.Issued = nil
		vcCopy.ID = ""

		raw, err = vcCopy.raw()
	} else {
		raw, err = vc.raw()
	}

	if err != nil {
		return nil, err
	}

	// If a Credential was parsed from JWT, we don't want the original JWT included when marshaling back to JWT claims.
	raw.JWT = ""

	vcMap, err := jsonutil.MergeCustomFields(raw, raw.CustomFields)
	if err != nil {
		return nil, err
	}

	credClaims := &JWTCredClaims{
		Claims: jwtClaims,
		VC:     vcMap,
	}

	return credClaims, nil
}

// JWTCredClaimsUnmarshaller unmarshals verifiable credential bytes into JWT claims with extra "vc" claim.
type JWTCredClaimsUnmarshaller func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error)

// decodeCredJWT parses JWT from the specified bytes array in compact format using unmarshaller.
// It returns jwt.JSONWebToken and decoded Verifiable Credential refined by JWT Claims in raw byte array form.
func decodeCredJWT(rawJWT string, unmarshaller JWTCredClaimsUnmarshaller) (jose.Headers, []byte, error) {
	joseHeaders, credClaims, err := unmarshaller(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal VC JWT claims: %w", err)
	}

	// Apply VC-related claims from JWT.
	credClaims.refineFromJWTClaims()

	vcData, err := json.Marshal(credClaims.VC)
	if err != nil {
		return nil, nil, errors.New("failed to marshal 'vc' claim of JWT")
	}

	return joseHeaders, vcData, nil
}

func (jcc *JWTCredClaims) refineFromJWTClaims() {
	vcMap := jcc.VC
	claims := jcc.Claims

	if iss := claims.Issuer; iss != "" {
		refineVCIssuerFromJWTClaims(vcMap, iss)
	}

	if nbf := claims.NotBefore; nbf != nil {
		nbfTime := nbf.Time().UTC()
		vcMap[vcIssuanceDateField] = nbfTime.Format(time.RFC3339)
	}

	if jti := claims.ID; jti != "" {
		vcMap[vcIDField] = jti
	}

	if iat := claims.IssuedAt; iat != nil {
		iatTime := iat.Time().UTC()
		vcMap[vcIssuanceDateField] = iatTime.Format(time.RFC3339)
	}

	if exp := claims.Expiry; exp != nil {
		expTime := exp.Time().UTC()
		vcMap[vcExpirationDateField] = expTime.Format(time.RFC3339)
	}
}

func refineVCIssuerFromJWTClaims(vcMap map[string]interface{}, iss string) {
	// Issuer of Verifiable Credential could be either string (id) or struct (with "id" field).
	if _, exists := vcMap[vcIssuerField]; !exists {
		vcMap[vcIssuerField] = iss
		return
	}

	switch issuer := vcMap[vcIssuerField].(type) {
	case string:
		vcMap[vcIssuerField] = iss
	case map[string]interface{}:
		issuer[vcIssuerIDField] = iss
	}
}
