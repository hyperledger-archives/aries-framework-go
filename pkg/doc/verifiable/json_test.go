/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type testJSON struct {
	S []string `json:"stringSlice"`
	I int      `json:"intValue"`
}

type testJSONInvalid struct {
	I []string `json:"intValue"`
	S int      `json:"stringSlice"`
}

func Test_marshalJSON(t *testing.T) {
	t.Run("Successful JSON marshaling", func(t *testing.T) {
		v := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}

		cf := map[string]interface{}{
			"boolValue": false,
			"intValue":  8,
		}
		actual, err := marshalWithCustomFields(&v, cf)
		require.NoError(t, err)

		expectedMap := map[string]interface{}{
			"stringSlice": []string{"a", "b", "c"},
			"intValue":    7,
			"boolValue":   false,
		}
		expected, err := json.Marshal(expectedMap)
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	})

	t.Run("Failed JSON marshall", func(t *testing.T) {
		// artificial example - pass smth which cannot be marshalled
		jsonBytes, err := marshalWithCustomFields(make(chan int), map[string]interface{}{})
		require.Error(t, err)
		require.Nil(t, jsonBytes)
	})
}

func Test_unmarshalJSON(t *testing.T) {
	originalMap := map[string]interface{}{
		"stringSlice": []string{"a", "b", "c"},
		"intValue":    7,
		"boolValue":   false,
	}

	data, err := json.Marshal(originalMap)
	require.NoError(t, err)

	t.Run("Successful JSON unmarshalling", func(t *testing.T) {
		v := new(testJSON)
		cf := make(map[string]interface{})
		err := unmarshalWithCustomFields(data, v, cf)
		require.NoError(t, err)

		expectedV := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}
		expectedEf := map[string]interface{}{
			"boolValue": false,
		}
		require.Equal(t, expectedV, *v)
		require.Equal(t, expectedEf, cf)
	})

	t.Run("Failed JSON unmarshalling", func(t *testing.T) {
		cf := make(map[string]interface{})

		// invalid JSON
		err := unmarshalWithCustomFields([]byte("not JSON"), "", cf)
		require.Error(t, err)

		// unmarshallable value
		err = unmarshalWithCustomFields(data, make(chan int), cf)
		require.Error(t, err)

		// incompatible structure of value
		err = unmarshalWithCustomFields(data, new(testJSONInvalid), cf)
		require.Error(t, err)
	})
}
