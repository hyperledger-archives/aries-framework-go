/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hybriddh

import (
	"crypto/elliptic"
	"crypto/rand"
	"strings"
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

func TestECDHESPrivateKeyManager_Primitive(t *testing.T) {
	km := newECDHESPrivateKeyManager()

	t.Run("Test private key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidECDHESPrivateKey.Error(),
			"ECDHESPrivate primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test private key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHESPrivateKey.Error(),
			"ECDHESPrivate primitive from bad serialized key must fail")
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
			tcName:    "private key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad hkdf hash type",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_UNKNOWN_HASH,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad EC Point Format",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_UNKNOWN_FORMAT,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key template URL",
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
			tcName:    "private key manager Primitive() using key with bad dem key size",
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
			d, x, y, err := elliptic.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = tt.curveType
			}

			pubKeyProto := &eciespb.EciesAeadHkdfPrivateKey{
				Version: v,
				PublicKey: &eciespb.EciesAeadHkdfPublicKey{
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
				},
				KeyValue: d,
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			require.EqualError(t, err, errInvalidECDHESPrivateKey.Error(),
				"ECDHESPrivate primitive from serialized key with invalid serialized key")
			require.Empty(t, p)
		})
	}
}

func TestEcdhesPrivateKeyManager_DoesSupport(t *testing.T) {
	km := newECDHESPrivateKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhesPrivateKeyTypeURL))
}

func TestEcdhesPrivateKeyManager_NewKey(t *testing.T) {
	km := newECDHESPrivateKeyManager()

	t.Run("Test private key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidECDHESPrivateKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHESPrivateKeyFormat.Error(),
			"ECDHESPrivate NewKey() from bad serialized key must fail")
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
		curveType commonpb.EllipticCurveType
		hashType  commonpb.HashType
		ecPtFmt   commonpb.EcPointFormat
		dekTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "success private key manager NewKey() and NewKeyData()",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad curve",
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad hkdf hash type",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_UNKNOWN_HASH,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad EC Point Format",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			hashType:  commonpb.HashType_SHA256,
			ecPtFmt:   commonpb.EcPointFormat_UNKNOWN_FORMAT,
			dekTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key template URL",
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
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad dem key size",
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

			privKeyProto := &eciespb.EciesAeadHkdfKeyFormat{
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
			}

			sPrivKey, err := proto.Marshal(privKeyProto)
			require.NoError(t, err)

			p, err := km.NewKey(sPrivKey)
			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)

				kd, errKD := km.NewKeyData(sPrivKey)
				require.NoError(t, errKD)
				require.NotEmpty(t, kd)
				require.Equal(t, kd.TypeUrl, ecdhesPrivateKeyTypeURL)
				require.Equal(t, kd.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
				return
			}

			require.EqualError(t, err, errInvalidECDHESPrivateKeyFormat.Error(),
				"ECDHESPrivate NewKey from serialized key with invalid serialized key")
			require.Empty(t, p)

			kd, err := km.NewKeyData(sPrivKey)
			require.Error(t, err)
			require.Empty(t, kd)
		})
	}
}
