/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms-go/doc/jose"
)

func TestUnsecuredJWT(t *testing.T) {
	headers := jose.Headers{"alg": "none"}
	claims := map[string]interface{}{"sub": "user123", "productIds": []interface{}{1., 2.}}

	serializedJWT, err := marshalUnsecuredJWT(headers, claims)
	require.NoError(t, err)
	require.NotEmpty(t, serializedJWT)

	var claimsParsed map[string]interface{}
	joseHeaders, err := unmarshalUnsecuredJWT(serializedJWT, &claimsParsed)
	require.NoError(t, err)

	require.Equal(t, claims, claimsParsed)
	require.Equal(t, joseHeaders, headers)

	// marshal with invalid claims
	invalidClaims := map[string]interface{}{"error": map[chan int]interface{}{make(chan int): 6}}
	serializedJWT, err = marshalUnsecuredJWT(headers, invalidClaims)
	require.Error(t, err)
	require.Contains(t, err.Error(), "marshal unsecured JWT")
	require.Empty(t, serializedJWT)

	// unmarshal invalid JWT
	joseHeaders, err = unmarshalUnsecuredJWT("not a valid compact serialized JWT", &claimsParsed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "marshal unsecured JWT")
	require.Empty(t, serializedJWT)
	require.Empty(t, joseHeaders)
}
