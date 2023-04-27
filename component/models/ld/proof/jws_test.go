/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/ld/testutil"
	afgotime "github.com/hyperledger/aries-framework-go/component/models/util/time"
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
		Created:      afgotime.NewTime(created),
		JWS:          "eyJ0eXAiOiJK..gFWFOEjXk",
		ProofPurpose: "assertionMethod",
	}

	var doc map[string]interface{}
	err = json.Unmarshal([]byte(validDoc), &doc)
	require.NoError(t, err)

	// happy path - no proof compaction
	proofVerifyData, err := createVerifyJWS(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotEmpty(t, proofVerifyData)

	// happy path - with proof compaction
	proofVerifyData, err = createVerifyJWS(
		&mockSignatureSuite{compactProof: true}, doc, p, testutil.WithDocumentLoader(t))
	require.NoError(t, err)
	require.NotEmpty(t, proofVerifyData)

	// artificial example - failure of doc canonization
	doc["type"] = 777
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid type value")
	require.Empty(t, proofVerifyData)

	// invalid JWT passed (we need to read a header from it to prepare verify data)
	doc["type"] = "Ed25519Signature2018"
	p.JWS = "invalid jws"
	proofVerifyData, err = createVerifyJWS(&mockSignatureSuite{}, doc, p, testutil.WithDocumentLoader(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid JWT")
	require.Empty(t, proofVerifyData)
}

func TestCreateDetachedJWTHeader(t *testing.T) {
	getJwtHeaderMap := func(jwtHeaderB64 string) map[string]interface{} {
		jwtHeaderBytes, err := base64.RawURLEncoding.DecodeString(jwtHeaderB64)
		require.NoError(t, err)

		var jwtHeaderMap map[string]interface{}
		err = json.Unmarshal(jwtHeaderBytes, &jwtHeaderMap)
		require.NoError(t, err)

		return jwtHeaderMap
	}

	jwtHeader := CreateDetachedJWTHeader("EdDSA")
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap := getJwtHeaderMap(jwtHeader)
	require.Equal(t, "EdDSA", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])

	jwtHeader = CreateDetachedJWTHeader("ES256K")
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap = getJwtHeaderMap(jwtHeader)
	require.Equal(t, "ES256K", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])

	jwtHeader = CreateDetachedJWTHeader("EdDSA")
	require.NotEmpty(t, jwtHeader)

	jwtHeaderMap = getJwtHeaderMap(jwtHeader)
	require.Equal(t, "EdDSA", jwtHeaderMap["alg"])
	require.Equal(t, false, jwtHeaderMap["b64"])
	require.Equal(t, []interface{}{"b64"}, jwtHeaderMap["crit"])
}

func TestGetJWTSignature(t *testing.T) {
	jwtSignature := base64.RawURLEncoding.EncodeToString([]byte("test signature"))
	jws := "header.payload." + jwtSignature

	// happy path
	signature, err := GetJWTSignature(jws)
	require.NoError(t, err)
	require.Equal(t, []byte("test signature"), signature)

	// not JWS
	signature, err = GetJWTSignature("incorrect JWS structure")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, signature)

	// empty signature (unsecured JWT)
	signature, err = GetJWTSignature("header.payload.")
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWT")
	require.Empty(t, signature)
}
