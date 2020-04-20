/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/stretchr/testify/require"
)

func TestGetCurveType(t *testing.T) {
	tcs := []struct {
		tcName       string
		curveName    string
		expectedType commonpb.EllipticCurveType
		isError      bool
	}{
		{
			tcName:       "test get secp256r1 curve type",
			curveName:    "secp256r1",
			expectedType: commonpb.EllipticCurveType_NIST_P256,
			isError:      false,
		},
		{
			tcName:       "test get NIST_P256 curve type",
			curveName:    "NIST_P256",
			expectedType: commonpb.EllipticCurveType_NIST_P256,
			isError:      false,
		},
		{
			tcName:       "test get P-256 curve type",
			curveName:    "P-256",
			expectedType: commonpb.EllipticCurveType_NIST_P256,
			isError:      false,
		},
		{
			tcName:       "test get EllipticCurveType_NIST_P256 curve type",
			curveName:    "EllipticCurveType_NIST_P256",
			expectedType: commonpb.EllipticCurveType_NIST_P256,
			isError:      false,
		},
		{
			tcName:       "test get secp384r1 curve type",
			curveName:    "secp384r1",
			expectedType: commonpb.EllipticCurveType_NIST_P384,
			isError:      false,
		},
		{
			tcName:       "test get NIST_P384 curve type",
			curveName:    "NIST_P384",
			expectedType: commonpb.EllipticCurveType_NIST_P384,
			isError:      false,
		},
		{
			tcName:       "test get P-384 curve type",
			curveName:    "P-384",
			expectedType: commonpb.EllipticCurveType_NIST_P384,
			isError:      false,
		},
		{
			tcName:       "test get EllipticCurveType_NIST_P384 curve type",
			curveName:    "EllipticCurveType_NIST_P384",
			expectedType: commonpb.EllipticCurveType_NIST_P384,
			isError:      false,
		},
		{
			tcName:       "test get secp521r1 curve type",
			curveName:    "secp521r1",
			expectedType: commonpb.EllipticCurveType_NIST_P521,
			isError:      false,
		},
		{
			tcName:       "test get NIST_P521 curve type",
			curveName:    "NIST_P521",
			expectedType: commonpb.EllipticCurveType_NIST_P521,
			isError:      false,
		},
		{
			tcName:       "test get P-521 curve type",
			curveName:    "P-521",
			expectedType: commonpb.EllipticCurveType_NIST_P521,
			isError:      false,
		},
		{
			tcName:       "test get EllipticCurveType_NIST_P521 curve type",
			curveName:    "EllipticCurveType_NIST_P521",
			expectedType: commonpb.EllipticCurveType_NIST_P521,
			isError:      false,
		},
		{
			tcName:       "test unsupported curve type",
			curveName:    "bad.curve",
			expectedType: 0,
			isError:      true,
		},
	}

	for _, tc := range tcs {
		tt := tc

		t.Run(tt.tcName, func(t *testing.T) {
			c, err := GetCurveType(tt.curveName)
			if tt.isError {
				require.Error(t, err)
				require.Zero(t, c)

				return
			}

			require.NoError(t, err)
			require.EqualValues(t, c.String(), tt.expectedType.String())
		})
	}
}
