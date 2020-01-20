/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDIDCommMsg(t *testing.T) {
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
		err:     `invalid payload data format: json: cannot unmarshal array into Go value of type service.DIDCommMsg`,
	}}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			val, err := NewDIDCommMsgMap(tc.payload)
			if err != nil {
				require.Contains(t, err.Error(), tc.err)
				require.Nil(t, val)
			} else {
				require.NotNil(t, val)
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
		name: "ID without Thread ID",
		msg:  DIDCommMsgMap{jsonID: "ID"},
		val:  "ID",
		err:  "",
	}, {
		name: "Thread ID with ID",
		msg:  DIDCommMsgMap{jsonID: "ID", jsonThread: map[string]interface{}{jsonThreadID: "thID"}},
		val:  "thID",
		err:  "",
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
