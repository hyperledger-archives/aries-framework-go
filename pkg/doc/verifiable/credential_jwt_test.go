/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"testing"
	"time"

	"github.com/square/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

func TestDecodeJWT(t *testing.T) {
	_, err := decodeCredJWT([]byte{}, func(vcJWTBytes []byte) (*JWTCredClaims, error) {
		return nil, errors.New("cannot parse JWT claims")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse JWT claims")
}

func TestRefineVcFromJwtClaims(t *testing.T) {
	issuerID := "did:example:76e12ec712ebc6f1c221ebfeb1f"
	issued := time.Date(2019, time.August, 10, 0, 0, 0, 0, time.UTC)
	vcID := "http://example.edu/credentials/3732"
	expired := time.Date(2029, time.August, 10, 0, 0, 0, 0, time.UTC)

	vcMap := map[string]interface{}{
		"issuer": "unknown",
	}
	credClaims := &jwt.Claims{
		Issuer:    issuerID,
		NotBefore: jwt.NewNumericDate(issued),
		ID:        vcID,
		IssuedAt:  jwt.NewNumericDate(issued),
		Expiry:    jwt.NewNumericDate(expired),
	}

	jwtCredClaims := &JWTCredClaims{
		Claims: credClaims,
		VC:     vcMap,
	}

	jwtCredClaims.refineFromJWTClaims()

	require.Equal(t, issuerID, vcMap["issuer"])
	require.Equal(t, "2019-08-10T00:00:00Z", vcMap["issuanceDate"])
	require.Equal(t, "2029-08-10T00:00:00Z", vcMap["expirationDate"])
}
