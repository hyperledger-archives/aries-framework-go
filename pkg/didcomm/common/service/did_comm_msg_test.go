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

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
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
			name: "Bad type ID (old)",
			msg:  DIDCommMsgMap{jsonIDV1: map[int]int{}},
		},
		{
			name: "Bad type ID",
			msg:  DIDCommMsgMap{jsonIDV2: map[int]int{}},
		},
		{
			name:     "Success (old)",
			msg:      DIDCommMsgMap{jsonIDV1: "ID"},
			expected: "ID",
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonIDV2: "ID"},
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

	DIDCommMsgMap.SetID(nil, ID)

	m := DIDCommMsgMap{}
	m.SetID(ID)

	require.Equal(t, ID, m.ID())
}

func TestDIDCommMsgMap_SetThread(t *testing.T) {
	const (
		ID  = "ID"
		PID = "PID"
	)

	DIDCommMsgMap.SetThread(nil, ID, PID)

	empty := DIDCommMsgMap{}
	empty.SetThread("", "")
	require.Equal(t, DIDCommMsgMap{}, empty)

	m := DIDCommMsgMap{}
	m.SetID("ID")
	m.SetThread(ID, PID)

	thid, err := m.ThreadID()
	require.NoError(t, err)
	require.Equal(t, ID, thid)
	require.Equal(t, PID, m.ParentThreadID())

	require.Equal(t, len(m), 2)
	require.Equal(t, m[jsonIDV1], ID)
	require.Equal(t, m[jsonThread].(map[string]interface{})[jsonThreadID], ID)
	require.Equal(t, m[jsonThread].(map[string]interface{})[jsonParentThreadID], PID)
}

func TestDIDCommMsgMap_SetThreadV2(t *testing.T) {
	const (
		ID  = "ID"
		PID = "PID"
	)

	DIDCommMsgMap.SetThread(nil, ID, PID, WithVersion(V2))

	empty := DIDCommMsgMap{}
	empty.SetThread("", "", WithVersion(V2))
	require.Equal(t, DIDCommMsgMap{}, empty)

	m := DIDCommMsgMap{}
	m.SetID(ID, WithVersion(V2))
	m.SetThread(ID, PID, WithVersion(V2))

	thid, err := m.ThreadID()
	require.NoError(t, err)
	require.Equal(t, ID, thid)
	require.Equal(t, PID, m.ParentThreadID())

	require.Equal(t, len(m), 3)
	require.Equal(t, m[jsonIDV2], ID)
	require.Equal(t, m[jsonThreadID], ID)
	require.Equal(t, m[jsonParentThreadID], PID)
}

func TestDIDCommMsgMap_UnsetThread(t *testing.T) {
	const (
		ID  = "ID"
		PID = "PID"
	)

	DIDCommMsgMap.UnsetThread(nil)

	m := DIDCommMsgMap{}
	m.SetThread(ID, PID)
	m.UnsetThread()

	require.Equal(t, DIDCommMsgMap{}, m)
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
			name: "Bad type Type (old)",
			msg:  DIDCommMsgMap{jsonTypeV1: map[int]int{}},
		},
		{
			name: "Bad type Type",
			msg:  DIDCommMsgMap{jsonTypeV2: map[int]int{}},
		},
		{
			name:     "Success (old)",
			msg:      DIDCommMsgMap{jsonTypeV1: "Type"},
			expected: "Type",
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonTypeV2: "Type"},
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
			name:     "Success (pthid)",
			msg:      DIDCommMsgMap{jsonParentThreadID: "pID"},
			expected: "pID",
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonThread: map[string]interface{}{jsonParentThreadID: "pthID"}},
			expected: "pthID",
		},
		{
			name: "Success (both are present)",
			msg: DIDCommMsgMap{
				jsonParentThreadID: "pID",
				jsonThread:         map[string]interface{}{jsonParentThreadID: "pthID"},
			},
			expected: "pID",
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

func TestIsDIDCommV2(t *testing.T) {
	tests := []struct {
		name   string
		msg    DIDCommMsgMap
		res    bool
		errStr string
	}{
		{
			name: "has v1 ID",
			msg: DIDCommMsgMap{
				"@id": "foo",
			},
			res:    false,
			errStr: "",
		},
		{
			name: "has v1 type",
			msg: DIDCommMsgMap{
				"@type": "foo",
			},
			res:    false,
			errStr: "",
		},
		{
			name: "has v2 ID",
			msg: DIDCommMsgMap{
				"id": "foo",
			},
			res:    true,
			errStr: "",
		},
		{
			name: "has v2 type",
			msg: DIDCommMsgMap{
				"type": "foo",
			},
			res:    true,
			errStr: "",
		},
		{
			name:   "error on empty message",
			msg:    DIDCommMsgMap{},
			res:    false,
			errStr: "not a valid didcomm v1 or v2 message",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := IsDIDCommV2(&tc.msg)

			require.Equal(t, tc.res, res)

			if tc.errStr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errStr)
			}
		})
	}
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

func TestDIDCommMsgMap_ToJsonDIDDoc(t *testing.T) {
	const sample = `{
       "connection": {
          "did_doc": {
            "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
			"id": "ac881ac9-47b1-485f-8509-cd1e382bfe59",
			"@type": "https://sampleorg.io/sample-type/1.0/sample-request",
			"~purpose": ["sample-purpose"],
			"~thread": {"thid": "ac881ac9-47b1-485f-8509-cd1e382bfe59"},
			"~transport": {"~return_route": "all"}
          }
       }
	}`

	msg := DIDCommMsgMap{}

	err := msg.UnmarshalJSON([]byte(sample))
	require.NoError(t, err)

	req := struct {
		Connection *struct {
			Doc did.Doc `json:"did_doc"`
		} `json:"connection"`
	}{}

	err = msg.Decode(&req)
	require.NoError(t, err)
	require.NotEmpty(t, req.Connection.Doc)
}
