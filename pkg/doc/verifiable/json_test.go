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

		ef := map[string]interface{}{
			"boolValue": false,
			"intValue":  8,
		}
		actual, err := marshalWithExtraFields(&v, ef)
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
		_, err := marshalWithExtraFields(make(chan int), map[string]interface{}{})
		require.Error(t, err)
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
		ef := make(map[string]interface{})
		err := unmarshalWithExtraFields(data, v, ef)
		require.NoError(t, err)

		expectedV := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}
		expectedEf := map[string]interface{}{
			"boolValue": false,
		}
		require.Equal(t, expectedV, *v)
		require.Equal(t, expectedEf, ef)
	})

	t.Run("Failed JSON unmarshalling", func(t *testing.T) {
		ef := make(map[string]interface{})

		// invalid JSON
		err := unmarshalWithExtraFields([]byte("not JSON"), "", ef)
		require.Error(t, err)

		// unmarshallable value
		err = unmarshalWithExtraFields(data, make(chan int), ef)
		require.Error(t, err)

		// incompatible structure of value
		err = unmarshalWithExtraFields(data, new(testJSONInvalid), ef)
		require.Error(t, err)
	})
}
