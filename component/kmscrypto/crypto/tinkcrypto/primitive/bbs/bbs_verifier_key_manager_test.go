/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/google/tink/go/subtle"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

func TestVerifierKeyManager_Primitive(t *testing.T) {
	km := newBBSVerifierKeyManager()

	t.Run("Test verifier key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidBBSVerifierKey.Error(),
			"newBBSVerifierKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test public key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidBBSVerifierKey.Error(),
			"newBBSVerifierKeyManager primitive from bad serialized key must fail")
		require.Empty(t, p)
	})

	flagTests := []struct {
		tcName     string
		version    uint32
		hashType   commonpb.HashType
		curveType  bbspb.BBSCurveType
		groupField bbspb.GroupField
	}{
		{
			tcName:     "verifier key manager Primitive() success",
			version:    0,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "verifier key manager Primitive() using key with bad version",
			version:    9999,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "verifier key manager Primitive() using key with bad hash type",
			version:    0,
			hashType:   commonpb.HashType_UNKNOWN_HASH,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "verifier key manager Primitive() using key with bad curve",
			version:    0,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_UNKNOWN_BBS_CURVE_TYPE,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager Primitive() using key with bad group",
			version:    0,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_UNKNOWN_GROUP_FIELD,
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			h := tt.hashType
			v := tt.version

			// temporarily reset hashType if its unknown type so manual key creation below doesn't fail
			if tt.hashType == commonpb.HashType_UNKNOWN_HASH {
				h = commonpb.HashType_SHA256
			}

			pubKey, _, err := bbs12381g2pub.GenerateKeyPair(subtle.GetHashFunc(h.String()), nil)
			require.NoError(t, err)

			pubKeyBytes, err := pubKey.Marshal()
			require.NoError(t, err)

			h = tt.hashType

			// set back hashType if it was unknown to proceed with the test
			if tt.hashType.String() == commonpb.HashType_UNKNOWN_HASH.String() {
				h = tt.hashType
			}

			pubKeyProto := &bbspb.BBSPublicKey{
				Version: v,
				Params: &bbspb.BBSParams{
					HashType: h,
					Curve:    tt.curveType,
					Group:    tt.groupField,
				},
				KeyValue: pubKeyBytes,
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)
				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}

func TestVerifierKeyManager_DoesSupport(t *testing.T) {
	km := newBBSVerifierKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(bbsVerifierKeyTypeURL))
}

func TestVerifierKeyManager_NewKeyAndNewKeyData(t *testing.T) {
	km := newBBSVerifierKeyManager()

	t.Run("Test public key manager NewKey()", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, "bbs_verifier_key_manager: NewKey not implemented")
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKeyData()", func(t *testing.T) {
		p, err := km.NewKeyData(nil)
		require.EqualError(t, err, "bbs_verifier_key_manager: NewKeyData not implemented")
		require.Empty(t, p)
	})
}
