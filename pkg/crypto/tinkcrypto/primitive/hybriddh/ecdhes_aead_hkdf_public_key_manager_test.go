/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hybriddh

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	eciespb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

func TestECDHESPublicKeyManager_Primitive(t *testing.T) {
	km := newECDHESPublicKeyManager()

	t.Run("Test public key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidECDHESPublicKey.Error(),
			"ECDHESPublic primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test public key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHESPublicKey.Error(),
			"ECDHESPublic primitive from bad serialized key must fail")
		require.Empty(t, p)
	})

	format := &gcmpb.AesGcmKeyFormat{
		KeySize: 32,
	}
	serializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	format = &gcmpb.AesGcmKeyFormat{
		KeySize: 99, // bad AES128GCM size
	}

	badSerializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	var flagTests = []struct {
		tcName    string
		version   uint32
		curveType commonpb.EllipticCurveType
		hashType  commonpb.HashType
		ecPtFmt   commonpb.EcPointFormat
		dekTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "public key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad hkdf hash type",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_UNKNOWN_HASH,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad EC Point Format",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_UNKNOWN_FORMAT,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "public key manager Primitive() using key with bad dem key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp: &tinkpb.KeyTemplate{
				TypeUrl:          aesGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	// nolint:scopelint
	for _, tt := range flagTests {
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			c := tt.curveType
			ht := tt.hashType
			salt := []byte("some salt")
			dekT := tt.dekTmp
			ptFmt := tt.ecPtFmt
			v := tt.version

			// temporarily reset curvType if its unknown type so subtle.GetCurve() below doesn't fail
			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = commonpb.EllipticCurveType_NIST_P256
			}

			crv, err := subtle.GetCurve(c.String())
			require.NoError(t, err)
			_, x, y, err := elliptic.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = tt.curveType
			}

			pubKeyProto := &eciespb.EciesAeadHkdfPublicKey{
				Version: v, // if v > 0  to force an error when calling km.Primitive()
				Params: &eciespb.EciesAeadHkdfParams{
					KemParams: &eciespb.EciesHkdfKemParams{
						CurveType:    c,  // unknown curve type to force an error when calling km.Primitive()
						HkdfHashType: ht, // unknown hkdf hash type to force an error when calling km.Primitive()
						HkdfSalt:     salt,
					},
					DemParams: &eciespb.EciesAeadDemParams{
						AeadDem: dekT, // invalid data enc key template to force an error when calling km.Primitive()
					},
					EcPointFormat: ptFmt, // unknown EC Pint format type to force an error when calling km.Primitive()
				},
				X: x.Bytes(),
				Y: y.Bytes(),
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			require.EqualError(t, err, errInvalidECDHESPublicKey.Error(),
				"ECDHESPublic primitive from serialized key with invalid serialized key")
			require.Empty(t, p)
		})
	}
}

func TestEcdhesPublicKeyManager_DoesSupport(t *testing.T) {
	km := newECDHESPublicKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhesPublicKeyTypeURL))
}

func TestEcdhesPublicKeyManager_NewKey(t *testing.T) {
	km := newECDHESPublicKeyManager()
	k, err := km.NewKey(nil)
	require.EqualError(t, err, "public key manager does not implement NewKey")
	require.Empty(t, k)
}

func TestEcdhesPublicKeyManager_NewKeyData(t *testing.T) {
	km := newECDHESPublicKeyManager()
	kd, err := km.NewKeyData(nil)
	require.EqualError(t, err, "public key manager does not implement NewKeyData")
	require.Empty(t, kd)
}
