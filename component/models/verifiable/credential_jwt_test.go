/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
)

func TestDecodeJWT(t *testing.T) {
	joseHeaders, vcBytes, err := decodeCredJWT("", func(string) (jose.Headers, *JWTCredClaims, error) {
		return nil, nil, errors.New("cannot parse JWT claims")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse JWT claims")
	require.Nil(t, vcBytes)
	require.Nil(t, joseHeaders)
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
		NotBefore: josejwt.NewNumericDate(issued),
		ID:        vcID,
		IssuedAt:  josejwt.NewNumericDate(issued),
		Expiry:    josejwt.NewNumericDate(expired),
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

func TestJWTCredClaims_ToSDJWTCredentialPayload(t *testing.T) {
	jcc := &JWTCredClaims{
		Claims: &jwt.Claims{
			Issuer:    "issuer",
			Subject:   "subject",
			Audience:  josejwt.Audience{"leela", "fry"},
			NotBefore: josejwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
			ID:        "http://example.edu/credentials/3732",
		},
		VC: map[string]interface{}{
			"@context": []interface{}{
				"https://www.w3.org/2018/credentials/v1",
				"https://trustbloc.github.io/context/vc/examples-v1.jsonld",
			},
			"id":   "http://example.edu/credentials/1989",
			"type": "VerifiableCredential",
			"credentialSubject": map[string]interface{}{
				"id": "did:example:iuajk1f712ebc6f1c276e12ec21",
			},
			"issuer": map[string]interface{}{
				"id":   "did:example:09s12ec712ebc6f1c671ebfeb1f",
				"name": "Example University",
			},
			"issuanceDate": "2020-01-01T10:54:01Z",
			"credentialStatus": map[string]interface{}{
				"id":   "https://example.gov/status/65",
				"type": "CredentialStatusList2017",
			},
		},
	}

	got, err := jcc.ToSDJWTV5CredentialPayload()
	require.NoError(t, err)
	require.NotContains(t, string(got), `"vc"`)

	var jccMapped *JWTCredClaims
	err = json.Unmarshal(got, &jccMapped)
	require.NoError(t, err)

	require.Equal(t, jcc, jccMapped)
}
