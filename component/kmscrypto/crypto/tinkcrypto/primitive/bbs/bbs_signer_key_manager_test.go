/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"strings"
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
)

func TestBBSignerKeyManager_Primitive(t *testing.T) {
	km := newBBSSignerKeyManager()

	t.Run("Test signer key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidBBSSignerKey.Error(),
			"bbsSignerKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test signer key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidBBSSignerKey.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
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
			tcName:     "signer key manager Primitive() success",
			version:    0,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager Primitive() using key with bad version",
			version:    9999,
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager Primitive() using key with bad hash type",
			version:    0,
			hashType:   commonpb.HashType_UNKNOWN_HASH,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager Primitive() using key with bad curve",
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
			v := tt.version

			privKeyProto := &bbspb.BBSPrivateKey{
				Version: v,
				PublicKey: &bbspb.BBSPublicKey{
					Version: v,
					Params: &bbspb.BBSParams{
						HashType: tt.hashType,
						Curve:    tt.curveType,
						Group:    tt.groupField,
					},
				},
			}

			sPrivKey, err := proto.Marshal(privKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPrivKey)
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

func TestBBSSignerKeyManager_DoesSupport(t *testing.T) {
	km := newBBSSignerKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(bbsSignerKeyTypeURL))
}

func TestBBSSignerKeyManager_NewKey(t *testing.T) {
	km := newBBSSignerKeyManager()

	t.Run("Test signer key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidBBSSignerKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test signer key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.Contains(t, err.Error(), errInvalidBBSSignerKey.Error())
		require.Contains(t, err.Error(), "invalid proto: proto:")
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
		require.Empty(t, p)
	})

	flagTests := []struct {
		tcName     string
		hashType   commonpb.HashType
		curveType  bbspb.BBSCurveType
		groupField bbspb.GroupField
	}{
		{
			tcName:     "success signer key manager NewKey() and NewKeyData()",
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager NewKey() and NewKeyData() using key with bad hash",
			hashType:   commonpb.HashType_UNKNOWN_HASH,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager NewKey() and NewKeyData() using key with bad curve",
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_UNKNOWN_BBS_CURVE_TYPE,
			groupField: bbspb.GroupField_G2,
		},
		{
			tcName:     "signer key manager NewKey() and NewKeyData() using key with bad group",
			hashType:   commonpb.HashType_SHA256,
			curveType:  bbspb.BBSCurveType_BLS12_381,
			groupField: bbspb.GroupField_UNKNOWN_GROUP_FIELD,
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			privKeyProto := &bbspb.BBSKeyFormat{
				Params: &bbspb.BBSParams{
					HashType: tt.hashType,
					Curve:    tt.curveType,
					Group:    tt.groupField,
				},
			}

			sPrivKey, err := proto.Marshal(privKeyProto)
			require.NoError(t, err)

			p, err := km.NewKey(sPrivKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)

				sp, e := proto.Marshal(p)
				require.NoError(t, e)
				require.NotEmpty(t, sp)

				// try PublicKeyData() with bad serialized private key
				pubK, e := km.PublicKeyData([]byte("bad serialized private key"))
				require.Error(t, e)
				require.Empty(t, pubK)

				// try PublicKeyData() with valid serialized private key
				pubK, e = km.PublicKeyData(sp)
				require.NoError(t, e)
				require.NotEmpty(t, pubK)
			}

			kd, err := km.NewKeyData(sPrivKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, kd)
				require.Equal(t, kd.TypeUrl, bbsSignerKeyTypeURL)
				require.Equal(t, kd.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}
