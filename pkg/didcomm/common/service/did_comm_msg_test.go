/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDIDCommMsgMap_ID(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		msg      DIDCommMsgMap
	}{
		{
			name: "Empty (nil msg)",
		},
		{
			name: "Empty",
			msg:  DIDCommMsgMap{},
		},
		{
			name: "Bad type ID",
			msg:  DIDCommMsgMap{jsonID: map[int]int{}},
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonID: "ID"},
			expected: "ID",
		},
	}

	for i := range tests {
		test := tests[i]

		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.msg.ID())
		})
	}
}

func TestDIDCommMsgMap_SetID(t *testing.T) {
	const ID = "ID"

	require.EqualError(t, DIDCommMsgMap.SetID(nil, ID), ErrNilMessage.Error())

	m := DIDCommMsgMap{}

	require.NoError(t, m.SetID(ID))
	require.Equal(t, ID, m.ID())
}

func TestDIDCommMsgMap_MetaData(t *testing.T) {
	tests := []struct {
		name     string
		expected map[string]interface{}
		msg      DIDCommMsgMap
	}{
		{
			name:     "Empty (nil msg)",
			msg:      DIDCommMsgMap{},
			expected: nil,
		},
		{
			name:     "Bad type Type",
			msg:      DIDCommMsgMap{jsonMetadata: map[int]int{}},
			expected: nil,
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonMetadata: map[string]interface{}{"key": "val"}},
			expected: map[string]interface{}{"key": "val"},
		},
	}

	for i := range tests {
		test := tests[i]

		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.msg.Metadata())
		})
	}
}

func TestDIDCommMsgMap_Type(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		msg      DIDCommMsgMap
	}{
		{
			name: "Empty (nil msg)",
		},
		{
			name: "Empty",
			msg:  DIDCommMsgMap{},
		},
		{
			name: "Bad type Type",
			msg:  DIDCommMsgMap{jsonType: map[int]int{}},
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonType: "Type"},
			expected: "Type",
		},
	}

	for i := range tests {
		test := tests[i]

		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.msg.Type())
		})
	}
}

func TestDIDCommMsgMap_Clone(t *testing.T) {
	tests := []struct {
		name     string
		expected DIDCommMsgMap
		msg      DIDCommMsgMap
	}{
		{
			name: "Empty (nil msg)",
		},
		{
			name:     "Empty",
			msg:      DIDCommMsgMap{},
			expected: DIDCommMsgMap{},
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonThread: map[string]int{}},
			expected: DIDCommMsgMap{jsonThread: map[string]int{}},
		},
		{
			name:     "Success with parent thread",
			msg:      DIDCommMsgMap{jsonThread: map[string]interface{}{jsonParentThreadID: "pthID"}},
			expected: DIDCommMsgMap{jsonThread: map[string]interface{}{jsonParentThreadID: "pthID"}},
		},
	}

	for i := range tests {
		test := tests[i]

		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.msg.Clone())
		})
	}
}

func TestDIDCommMsgMap_ParentThreadID(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		msg      DIDCommMsgMap
	}{
		{
			name: "Empty (nil msg)",
		},
		{
			name: "Empty",
			msg:  DIDCommMsgMap{},
		},
		{
			name: "Success",
			msg:  DIDCommMsgMap{jsonThread: map[string]int{}},
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonThread: map[string]interface{}{jsonParentThreadID: "pthID"}},
			expected: "pthID",
		},
	}

	for i := range tests {
		test := tests[i]

		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, test.msg.ParentThreadID())
		})
	}
}

func TestDIDCommMsgMap_ToStruct(t *testing.T) {
	type Test struct {
		Time  time.Time
		Bytes []byte
	}

	expected := Test{
		Time:  time.Now().UTC(),
		Bytes: []byte("payload"),
	}

	b, err := json.Marshal(expected)
	require.NoError(t, err)

	msg, err := ParseDIDCommMsgMap(b)
	require.NoError(t, err)

	actual := Test{}
	require.NoError(t, msg.Decode(&actual))
	require.Equal(t, expected, actual)
}

func TestDIDCommMsgMap_ToJsonRawStruct(t *testing.T) {
	const sample = `{
    "@id": "ac881ac9-47b1-485f-8509-cd1e382bfe59",
    "@type": "https://sampleorg.io/sample-type/1.0/sample-request",
    "data": {
        "doc": {
			"@id": "fh770bd8-58c2-596g-9610-de2f493cgf60",
            "created": "2020-10-08T16:22:23.2967447Z",
            "updated": "2020-10-08T16:22:23.2967447Z"
        }
    },
    "~purpose": ["sample-purpose"],
    "~thread": {"thid": "ac881ac9-47b1-485f-8509-cd1e382bfe59"},
    "~transport": {"~return_route": "all"}
	}`

	msg := DIDCommMsgMap{}

	err := msg.UnmarshalJSON([]byte(sample))
	require.NoError(t, err)

	req := struct {
		ID      string   `json:"@id"`
		Type    string   `json:"@type"`
		Purpose []string `json:"~purpose"`
		Data    *struct {
			Doc json.RawMessage `json:"doc"`
		} `json:"data"`
	}{}

	err = msg.Decode(&req)
	require.NoError(t, err)
	require.NotEmpty(t, req.Data.Doc)
}

func TestDIDCommMsgMap_MarshalJSON(t *testing.T) {
	const expected = `{"Name":"test"}`

	msg := NewDIDCommMsgMap(struct {
		Name string
	}{Name: "test"})
	msg.Metadata()["key"] = "val"

	actual, err := json.Marshal(msg)
	require.NoError(t, err)
	require.Equal(t, []byte(expected), actual)
	require.Equal(t, msg.Metadata()["key"], "val")
}

func TestDIDCommMsgMap_UnmarshalJSON(t *testing.T) {
	const expected = `{"Name":"test"}`

	msg := DIDCommMsgMap{}
	require.NoError(t, json.Unmarshal([]byte(expected), &msg))
	_, ok := msg[jsonMetadata]
	require.True(t, ok)
}
