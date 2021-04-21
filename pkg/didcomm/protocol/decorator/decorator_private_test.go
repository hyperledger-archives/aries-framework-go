/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_b64ToRawURL(t *testing.T) {
	testCases := []struct {
		in  []string
		out string
	}{
		{
			in:  []string{"___-_w", "___-_w==", "///+/w", "///+/w=="},
			out: "___-_w",
		},
		{
			in: []string{
				"Y29mZmVlIMD_7iBjb2ZmZWU",
				"Y29mZmVlIMD_7iBjb2ZmZWU=",
				"Y29mZmVlIMD/7iBjb2ZmZWU",
				"Y29mZmVlIMD/7iBjb2ZmZWU=",
			},
			out: "Y29mZmVlIMD_7iBjb2ZmZWU",
		},
		{
			in: []string{
				"ZGVhZGJlZWYg3q2-7yBkZWFkYmVlZg",
				"ZGVhZGJlZWYg3q2-7yBkZWFkYmVlZg==",
				"ZGVhZGJlZWYg3q2+7yBkZWFkYmVlZg",
				"ZGVhZGJlZWYg3q2+7yBkZWFkYmVlZg==",
			},
			out: "ZGVhZGJlZWYg3q2-7yBkZWFkYmVlZg",
		},
	}

	for _, testCase := range testCases {
		for _, in := range testCase.in {
			out := b64ToRawURL(in)
			require.Equal(t, testCase.out, out)
		}
	}
}
