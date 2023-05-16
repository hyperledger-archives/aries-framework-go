/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

// JWTPresClaims is JWT Claims extension by Verifiable Presentation (with custom "vp" claim).
type JWTPresClaims struct {
	*jwt.Claims

	Presentation *rawPresentation `json:"vp,omitempty"`
}

func (jpc *JWTPresClaims) refineFromJWTClaims() {
	raw := jpc.Presentation

	if jpc.Issuer != "" {
		raw.Holder = jpc.Issuer
	}

	if jpc.ID != "" {
		raw.ID = jpc.ID
	}
}

// newJWTPresClaims creates JWT Claims of VP with an option to minimize certain fields put into "vp" claim.
func newJWTPresClaims(vp *Presentation, audience []string, minimizeVP bool) (*JWTPresClaims, error) {
	// currently jwt encoding supports only single subject.([]Subject) (by the spec)
	jwtClaims := &jwt.Claims{
		Issuer: vp.Holder, // iss
		ID:     vp.ID,     // jti
	}
	if len(audience) > 0 {
		jwtClaims.Audience = audience
	}

	var (
		rawVP *rawPresentation
		err   error
	)

	if minimizeVP {
		vpCopy := *vp
		vpCopy.ID = ""
		vpCopy.Holder = ""
		rawVP, err = vpCopy.raw()
	} else {
		rawVP, err = vp.raw()
	}

	if err != nil {
		return nil, err
	}

	rawVP.JWT = ""

	presClaims := &JWTPresClaims{
		Claims:       jwtClaims,
		Presentation: rawVP,
	}

	return presClaims, nil
}

// JWTPresClaimsUnmarshaller parses JWT of certain type to JWT Claims containing "vp" (Presentation) claim.
type JWTPresClaimsUnmarshaller func(vpJWT string) (*JWTPresClaims, error)

// decodePresJWT parses JWT from the specified bytes array in compact format using the unmarshaller.
// It returns decoded Verifiable Presentation refined by JWT Claims in raw byte array and rawPresentation form.
func decodePresJWT(vpJWT string, unmarshaller JWTPresClaimsUnmarshaller) ([]byte, *rawPresentation, error) {
	presClaims, err := unmarshaller(vpJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("decode Verifiable Presentation JWT claims: %w", err)
	}

	// Apply VC-related claims from JWT.
	presClaims.refineFromJWTClaims()

	vpRaw := presClaims.Presentation

	rawBytes, err := json.Marshal(vpRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal \"vp\" claim of JWT: %w", err)
	}

	return rawBytes, vpRaw, nil
}
