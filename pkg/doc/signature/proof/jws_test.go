/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_getJWTHeader(t *testing.T) {
	jwtHeader, err := getJWTHeader("eyJ0eXAiOiJK..gFWFOEjXk")
	require.NoError(t, err)
	require.Equal(t, "eyJ0eXAiOiJK", jwtHeader)

	jwtHeader, err = getJWTHeader("invalid jwt")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, jwtHeader)
}

func Test_createVerifyJWS(t *testing.T) {
	created, err := time.Parse(time.RFC3339, "2018-03-15T00:00:00Z")
	require.NoError(t, err)

	p := &Proof{
		Type:         "Ed25519Signature2018",
		Created:      &created,
		JWS:          "eyJ0eXAiOiJK..gFWFOEjXk",
		ProofPurpose: "assertionMethod",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	proofVerifyData, err := createVerifyJWS(&mockSignatureSuite{}, doc, p)
	require.NoError(t, err)
	require.NotEmpty(t, proofVerifyData)

	// artificial example - failure of doc canonization
	doc["type"] = 777
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid type value")
	require.Empty(t, proofVerifyData)

	// invalid JWT passed (we need to read a header from it to prepare verify data)
	doc["type"] = "Ed25519Signature2018"
	p.JWS = "invalid jws"
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JWT")
	require.Empty(t, proofVerifyData)
}
