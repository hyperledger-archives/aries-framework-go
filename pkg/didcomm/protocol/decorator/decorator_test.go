/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttachmentData_Fetch(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		expected := map[string]interface{}{
			"FirstName": "John",
			"LastName":  "Doe",
		}
		bits, err := (&AttachmentData{JSON: expected}).Fetch()
		require.NoError(t, err)
		result := make(map[string]interface{})
		err = json.Unmarshal(bits, &result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("base64", func(t *testing.T) {
		expected := &testStruct{
			FirstName: "John",
			LastName:  "Doe",
		}
		tmp, err := json.Marshal(expected)
		require.NoError(t, err)
		encoded := base64.StdEncoding.EncodeToString(tmp)
		bytes, err := (&AttachmentData{Base64: encoded}).Fetch()
		require.NoError(t, err)
		result := &testStruct{}
		err = json.Unmarshal(bytes, result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("invalid json", func(t *testing.T) {
		_, err := (&AttachmentData{JSON: func() {}}).Fetch()
		require.Error(t, err)
	})
	t.Run("invalid base64", func(t *testing.T) {
		_, err := (&AttachmentData{Base64: "invalid"}).Fetch()
		require.Error(t, err)
	})
	t.Run("no contents", func(t *testing.T) {
		_, err := (&AttachmentData{}).Fetch()
		require.Error(t, err)
	})
}

type testStruct struct {
	FirstName string
	LastName  string
}
