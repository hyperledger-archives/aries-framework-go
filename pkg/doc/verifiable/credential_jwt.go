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

	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
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
		IssuedAt:  josejwt.NewNumericDate(vc.Issued.Time), // iat (not in spec, follow the interop project approach)
	}
	if vc.Expired != nil {
		jwtClaims.Expiry = josejwt.NewNumericDate(vc.Expired.Time) // exp
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

	vcMap, err := mergeCustomFields(raw, raw.CustomFields)
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
type JWTCredClaimsUnmarshaller func(vcJWTBytes string) (*JWTCredClaims, error)

// decodeCredJWT parses JWT from the specified bytes array in compact format using unmarshaller.
// It returns decoded Verifiable Credential refined by JWT Claims in raw byte array form.
func decodeCredJWT(rawJWT string, unmarshaller JWTCredClaimsUnmarshaller) ([]byte, error) {
	credClaims, err := unmarshaller(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VC JWT claims: %w", err)
	}

	// Apply VC-related claims from JWT.
	credClaims.refineFromJWTClaims()

	vcData, err := json.Marshal(credClaims.VC)
	if err != nil {
		return nil, errors.New("failed to marshal 'vc' claim of JWT")
	}

	return vcData, nil
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
