/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_serializableReqToPubKey_failures(t *testing.T) {
	flagTests := []struct {
		tcName     string
		sPubKeyReq *publicKeyReq
	}{
		{
			tcName: "publicKeyReq with bad KID encoded value",
			sPubKeyReq: &publicKeyReq{
				KID: "&",
			},
		},
		{
			tcName: "publicKeyReq with bad X encoded value",
			sPubKeyReq: &publicKeyReq{
				X: "&",
			},
		},
		{
			tcName: "publicKeyReq with bad Y encoded value",
			sPubKeyReq: &publicKeyReq{
				Y: "&",
			},
		},
		{
			tcName: "publicKeyReq with bad Curve encoded value",
			sPubKeyReq: &publicKeyReq{
				Curve: "&",
			},
		},
		{
			tcName: "publicKeyReq with bad Type encoded value",
			sPubKeyReq: &publicKeyReq{
				Type: "&",
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			_, err := serializableReqToPubKey(tt.sPubKeyReq)
			require.EqualError(t, err, "illegal base64 data at input byte 0")
		})
	}
}

func Test_serializableToWrappedKey_failures(t *testing.T) {
	flagTests := []struct {
		tcName    string
		sRecWKReq *recipientWrappedKeyReq
	}{
		{
			tcName: "sRecWKReq with bad KID encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				KID: "&",
			},
		},
		{
			tcName: "sRecWKReq with bad EncryptedCEK encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				EncryptedCEK: "&",
			},
		},
		{
			tcName: "sRecWKReq with bad EPK encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				EPK: publicKeyReq{
					KID: "&",
				},
			},
		},
		{
			tcName: "sRecWKReq with bad Alg encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				Alg: "&",
			},
		},
		{
			tcName: "sRecWKReq with bad APU encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				APU: "&",
			},
		},
		{
			tcName: "sRecWKReq with bad APV encoded value",
			sRecWKReq: &recipientWrappedKeyReq{
				APV: "&",
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			_, err := serializableToWrappedKey(tt.sRecWKReq)
			require.EqualError(t, err, "illegal base64 data at input byte 0")
		})
	}
}
