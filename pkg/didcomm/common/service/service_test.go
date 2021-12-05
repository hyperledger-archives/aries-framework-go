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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

func TestParseDIDCommMsgMap(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		err     string
	}{{
		name: "No payload",
		err:  "invalid payload data format: unexpected end of JSON input",
	}, {
		name:    "Happy path",
		payload: []byte(`{"@id":"ID"}`),
		err:     "",
	}, {
		name:    "Empty payload (JSON)",
		payload: []byte(`{}`),
		err:     "",
	}, {
		name:    "Array payload",
		payload: []byte(`[]`),
		err:     `invalid payload data format: json: cannot unmarshal array into Go value of type map[string]interface`,
	}, {
		name:    "Type",
		payload: []byte(`{"@type":"type"}`),
		err:     "",
	}}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			val, err := ParseDIDCommMsgMap(tc.payload)
			if err != nil {
				require.Contains(t, err.Error(), tc.err)
				require.Nil(t, val)
			} else {
				require.NotNil(t, val)
			}
		})
	}
}

func TestNewDIDCommMsgMap(t *testing.T) {
	tests := []struct {
		name     string
		payload  interface{}
		expected DIDCommMsgMap
		err      string
	}{
		{
			name: "Thread decorator",
			payload: struct {
				Time    time.Time
				Threads []decorator.Thread
				Thread  decorator.Thread
			}{
				Threads: []decorator.Thread{{
					ID:             "test",
					ReceivedOrders: map[string]int{"order": 1},
				}},
				Thread: decorator.Thread{
					ID:             "test",
					ReceivedOrders: map[string]int{"order": 1},
				},
			},
			expected: DIDCommMsgMap{
				jsonMetadata: map[string]interface{}{},
				"Thread": map[string]interface{}{
					"received_orders": map[string]interface{}{"order": 1},
					"thid":            "test",
				},
				"Threads": []interface{}{map[string]interface{}{
					"received_orders": map[string]interface{}{"order": 1},
					"thid":            "test",
				}},
				"Time": time.Time{},
			},
		},
		{
			name: "Ignore",
			payload: struct {
				Ignore string `json:"-"`
			}{
				Ignore: "Ignore",
			},
			expected: DIDCommMsgMap{
				jsonMetadata: map[string]interface{}{},
			},
		},
		{
			name: "Build-in",
			payload: struct {
				decorator.Thread
			}{
				Thread: decorator.Thread{
					ID:             "test",
					ReceivedOrders: map[string]int{"order": 1},
				},
			},
			expected: DIDCommMsgMap{
				jsonMetadata:      map[string]interface{}{},
				"received_orders": map[string]interface{}{"order": 1},
				"thid":            "test",
			},
		},
		{
			name: "Build-in with pointer",
			payload: struct {
				*decorator.Thread
			}{
				Thread: &decorator.Thread{
					ID:             "test",
					ReceivedOrders: map[string]int{"order": 1},
				},
			},
			expected: DIDCommMsgMap{
				jsonMetadata:      map[string]interface{}{},
				"received_orders": map[string]interface{}{"order": 1},
				"thid":            "test",
			},
		},
		{
			name: "Build-in with JSON tag",
			payload: struct {
				*decorator.Thread `json:"~thread"`
			}{
				Thread: &decorator.Thread{
					ID:             "test",
					ReceivedOrders: map[string]int{"order": 1},
				},
			},
			expected: DIDCommMsgMap{
				jsonMetadata: map[string]interface{}{},
				"~thread": map[string]interface{}{
					"received_orders": map[string]interface{}{"order": 1},
					"thid":            "test",
				},
			},
		},
	}

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			val := NewDIDCommMsgMap(tc.payload)
			require.Equal(t, tc.expected, val)

			eRes, err := json.Marshal(tc.payload)
			require.NoError(t, err)

			vRes, err := json.Marshal(val)
			require.NoError(t, err)

			eResMap := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(eRes, &eResMap))

			vResMap := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(vRes, &vResMap))

			require.Equal(t, eResMap, vResMap)
		})
	}

	idTests := []struct {
		name    string
		payload interface{}
		version Version
	}{
		{
			name: "v1 with ID",
			payload: struct {
				ID   string `json:"@id"`
				Type string `json:"@type"`
			}{
				ID:   "foobar",
				Type: "blahblah",
			},
			version: V1,
		},
		{
			name: "v2 with ID",
			payload: struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			}{
				ID:   "foobar",
				Type: "blahblah",
			},
			version: V2,
		},
		{
			name: "v1 without ID",
			payload: struct {
				Type string `json:"@type"`
			}{
				Type: "blahblah",
			},
			version: V1,
		},
		{
			name: "v2 without ID",
			payload: struct {
				Type string `json:"type"`
			}{
				Type: "blahblah",
			},
			version: V2,
		},
	}

	for _, tc := range idTests {
		t.Run(tc.name, func(t *testing.T) {
			msg := NewDIDCommMsgMap(tc.payload)

			_, hasIDV1 := msg["@id"]
			_, hasIDV2 := msg["id"]

			isV2, err := IsDIDCommV2(&msg)
			require.NoError(t, err)

			switch tc.version {
			case V1:
				require.True(t, hasIDV1)
				require.False(t, hasIDV2)
				require.False(t, isV2)
			case V2:
				require.False(t, hasIDV1)
				require.True(t, hasIDV2)
				require.True(t, isV2)
			}
		})
	}
}

func TestDIDCommMsg_ThreadID(t *testing.T) {
	tests := []struct {
		name string
		msg  DIDCommMsgMap
		val  string
		err  string
	}{{
		name: "No header",
		msg:  nil,
		err:  ErrInvalidMessage.Error(),
	}, {
		name: "old ID without Thread ID",
		msg:  DIDCommMsgMap{jsonIDV1: "ID"},
		val:  "ID",
		err:  "",
	}, {
		name: "ID without Thread ID",
		msg:  DIDCommMsgMap{jsonIDV2: "ID"},
		val:  "ID",
		err:  "",
	}, {
		name: "Thread ID",
		msg:  DIDCommMsgMap{jsonThreadID: "tID"},
		val:  "",
		err:  ErrInvalidMessage.Error(),
	}, {
		name: "Thread ID with ID",
		msg:  DIDCommMsgMap{jsonIDV2: "ID", jsonThreadID: "tID"},
		val:  "tID",
		err:  "",
	}, {
		name: "Thread ID with old ID",
		msg:  DIDCommMsgMap{jsonIDV1: "ID", jsonThreadID: "tID"},
		val:  "ID",
		err:  "",
	}, {
		name: "Thread ID with old ID",
		msg:  DIDCommMsgMap{jsonIDV1: "ID", jsonThread: map[string]interface{}{jsonThreadID: "thID"}},
		val:  "thID",
		err:  "",
	}, {
		name: "Thread ID with ID",
		msg:  DIDCommMsgMap{jsonIDV2: "ID", jsonThread: map[string]interface{}{jsonThreadID: "thID"}},
		val:  "",
		err:  ErrInvalidMessage.Error(),
	}, {
		name: "Thread ID without ID",
		msg:  DIDCommMsgMap{jsonThread: map[string]interface{}{jsonThreadID: "thID"}},
		val:  "",
		err:  ErrInvalidMessage.Error(),
	}, {
		name: "No Thread ID and ID",
		msg:  DIDCommMsgMap{},
		val:  "",
		err:  ErrThreadIDNotFound.Error(),
	}}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			val, err := tc.msg.ThreadID()
			if err != nil {
				require.Contains(t, err.Error(), tc.err)
			}
			require.Equal(t, tc.val, val)
		})
	}
}
