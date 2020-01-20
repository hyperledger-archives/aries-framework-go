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
			name:     "Empty (nil msg)",
			expected: "",
		},
		{
			name:     "Empty",
			msg:      DIDCommMsgMap{},
			expected: "",
		},
		{
			name:     "Bad type ID",
			msg:      DIDCommMsgMap{jsonID: map[int]int{}},
			expected: "",
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonID: "ID"},
			expected: "ID",
		},
	}

	for i := range tests {
		require.Equal(t, tests[i].expected, tests[i].msg.ID())
	}
}

func TestDIDCommMsgMap_Type(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		msg      DIDCommMsgMap
	}{
		{
			name:     "Empty (nil msg)",
			expected: "",
		},
		{
			name:     "Empty",
			msg:      DIDCommMsgMap{},
			expected: "",
		},
		{
			name:     "Bad type Type",
			msg:      DIDCommMsgMap{jsonType: map[int]int{}},
			expected: "",
		},
		{
			name:     "Success",
			msg:      DIDCommMsgMap{jsonType: "Type"},
			expected: "Type",
		},
	}

	for i := range tests {
		require.Equal(t, tests[i].expected, tests[i].msg.Type())
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

	msg, err := NewDIDCommMsgMap(b)
	require.NoError(t, err)

	actual := Test{}
	require.NoError(t, msg.Decode(&actual))
	require.Equal(t, expected, actual)
}
