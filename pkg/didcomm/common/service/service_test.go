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
