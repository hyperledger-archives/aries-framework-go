/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
)

func TestHeaders_GetJWK(t *testing.T) {
	headers := Headers{}

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwkKey := jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       pubKey,
			KeyID:     "kid",
			Algorithm: "EdDSA",
		},
	}

	jwkBytes, err := json.Marshal(&jwkKey)
	require.NoError(t, err)

	var jwkMap map[string]interface{}

	err = json.Unmarshal(jwkBytes, &jwkMap)
	require.NoError(t, err)

	headers["jwk"] = jwkMap

	parsedJWK, ok := headers.JWK()
	require.True(t, ok)
	require.NotNil(t, parsedJWK)

	// jwk is not present
	delete(headers, "jwk")
	parsedJWK, ok = headers.JWK()
	require.False(t, ok)
	require.Nil(t, parsedJWK)

	// jwk is not a map
	headers["jwk"] = "not a map"
	parsedJWK, ok = headers.JWK()
	require.False(t, ok)
	require.Nil(t, parsedJWK)
}
