/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
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
		err:     `invalid payload data format: json: cannot unmarshal array into Go value of type service.Header`,
	}}
	t.Parallel()
	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			val, err := NewDIDCommMsg(tc.payload)
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
		msg  DIDCommMsg
		val  string
		err  string
	}{{
		name: "No header",
		msg:  DIDCommMsg{},
		err:  ErrNoHeader.Error(),
	}, {
		name: "ID without Thread ID",
		msg:  DIDCommMsg{Header: &Header{ID: "ID"}},
		val:  "ID",
		err:  "",
	}, {
		name: "Thread ID with ID",
		msg:  DIDCommMsg{Header: &Header{ID: "ID", Thread: decorator.Thread{ID: "thID"}}},
		val:  "thID",
		err:  "",
	}, {
		name: "Thread ID without ID",
		msg:  DIDCommMsg{Header: &Header{Thread: decorator.Thread{ID: "thID"}}},
		val:  "",
		err:  ErrInvalidMessage.Error(),
	}, {
		name: "No Thread ID and ID",
		msg:  DIDCommMsg{Header: &Header{}},
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

func TestDIDCommMsg_Clone(t *testing.T) {
	var didMsg *DIDCommMsg
	require.Nil(t, didMsg)
	// clone nil DIDCommMsg
	require.Equal(t, didMsg, didMsg.Clone())

	// clone DIDCommMsg with Payload and modified Payload
	didMsg = &DIDCommMsg{Payload: []byte{0x1}}
	cloned := didMsg.Clone()
	require.Equal(t, didMsg, cloned)
	// modifies Payload
	didMsg.Payload[0] = 0x2
	require.NotEqual(t, didMsg, cloned)

	// clone DIDCommMsg with Payload and Header
	didMsg = &DIDCommMsg{Payload: []byte{0x1}, Header: &Header{
		ID:     "ID",
		Thread: decorator.Thread{ID: "ID"},
		Type:   "Type",
	}}
	cloned = didMsg.Clone()
	require.Equal(t, didMsg, cloned)
	// modifies Header
	didMsg.Header.ID = "newID"
	require.NotEqual(t, didMsg, cloned)
}
