/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestJwtAlgorithm_Jose(t *testing.T) {
	joseAlg, err := RS256.jose()
	require.NoError(t, err)
	require.Equal(t, jose.RS256, joseAlg)

	joseAlg, err = EdDSA.jose()
	require.NoError(t, err)
	require.Equal(t, jose.EdDSA, joseAlg)

	// not supported alg
	_, err = JWSAlgorithm(-1).jose()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
}

func TestStringSlice(t *testing.T) {
	strings, err := stringSlice([]interface{}{"str1", "str2"})
	require.NoError(t, err)
	require.Equal(t, []string{"str1", "str2"}, strings)

	_, err = stringSlice([]interface{}{"str1", 15})
	require.Error(t, err)
}

func TestTypedID_MarshalJSON(t *testing.T) {
	t.Run("Successful marshalling", func(t *testing.T) {
		tid := TypedID{
			ID:   "http://example.com/policies/credential/4",
			Type: "IssuerPolicy",
			CustomFields: map[string]interface{}{
				"profile": "http://example.com/profiles/credential",
			},
		}

		data, err := json.Marshal(&tid)
		require.NoError(t, err)

		var tidRecovered TypedID
		err = json.Unmarshal(data, &tidRecovered)
		require.NoError(t, err)

		require.Equal(t, tid, tidRecovered)
	})

	t.Run("Invalid marshalling", func(t *testing.T) {
		tid := TypedID{
			CustomFields: map[string]interface{}{
				"invalid": make(chan int),
			},
		}

		_, err := json.Marshal(&tid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal TypedID")
	})
}

func TestTypedID_UnmarshalJSON(t *testing.T) {
	t.Run("Successful unmarshalling", func(t *testing.T) {
		tidJSON := `{
  "type": "IssuerPolicy",
  "id": "http://example.com/policies/credential/4",
  "profile": "http://example.com/profiles/credential",
  "prohibition": [{
    "assigner": "https://example.edu/issuers/14",
    "assignee": "AllVerifiers",
    "target": "http://example.edu/credentials/3732"
  }]
}`

		var tid TypedID
		err := json.Unmarshal([]byte(tidJSON), &tid)
		require.NoError(t, err)

		require.Equal(t, "http://example.com/policies/credential/4", tid.ID)
		require.Equal(t, "IssuerPolicy", tid.Type)
		require.Equal(t, CustomFields{
			"profile": "http://example.com/profiles/credential",
			"prohibition": []interface{}{
				map[string]interface{}{
					"assigner": "https://example.edu/issuers/14",
					"assignee": "AllVerifiers",
					"target":   "http://example.edu/credentials/3732",
				},
			},
		}, tid.CustomFields)
	})

	t.Run("Invalid unmarshalling", func(t *testing.T) {
		tidJSONWithInvalidType := `{
  "type": 77
}`
		var tid TypedID
		err := json.Unmarshal([]byte(tidJSONWithInvalidType), &tid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal TypedID")
	})
}
