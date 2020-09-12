/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

func TestECDHESPrivateKeyManager_Primitive(t *testing.T) {
	km := newECDHESPrivateKeyManager()

	t.Run("Test private key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidECDHESAESPrivateKey.Error(),
			"ECDHESPrivate primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test private key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHESAESPrivateKey.Error(),
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

	flagTests := []struct {
		tcName    string
		version   uint32
		curveType commonpb.EllipticCurveType
		ecPtFmt   commonpb.EcPointFormat
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "private key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "success private key manager Primitive()",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_UNCOMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "private key manager Primitive() using key with bad dem key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          composite.AESGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			c := tt.curveType
			encT := tt.encTmp
			ptFmt := tt.ecPtFmt
			v := tt.version

			// temporarily reset curvType if its unknown type so subtle.GetCurve() below doesn't fail
			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = commonpb.EllipticCurveType_NIST_P256
			}

			crv, err := hybrid.GetCurve(c.String())
			require.NoError(t, err)
			d, x, y, err := elliptic.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			// set back curvType if it was unknown to proceed with the test
			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = tt.curveType
			}

			pubKeyProto := &ecdhespb.EcdhesAeadPrivateKey{
				Version: v,
				PublicKey: &ecdhespb.EcdhesAeadPublicKey{
					Version: v, // if v > 0  to force an error when calling km.Primitive()
					Params: &ecdhespb.EcdhesAeadParams{
						KwParams: &ecdhespb.EcdhesKwParams{
							CurveType: c, // unknown curve type to force an error when calling km.Primitive()
						},
						EncParams: &ecdhespb.EcdhesAeadEncParams{
							AeadEnc: encT, // invalid data enc key template to get an error when calling km.Primitive()
						},
						EcPointFormat: ptFmt,
					},
					X: x.Bytes(),
					Y: y.Bytes(),
				},
				KeyValue: d,
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			if bytes.Equal(tt.encTmp.Value, badSerializedFormat) {
				require.EqualError(t, err, errInvalidECDHESAESPrivateKey.Error(),
					"ECDHESPrivate primitive from serialized key with invalid serialized key")
				require.Empty(t, p)

				return
			}

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

func TestEcdhesPrivateKeyManager_DoesSupport(t *testing.T) {
	km := newECDHESPrivateKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhesAESPrivateKeyTypeURL))
}

func TestEcdhesPrivateKeyManager_NewKey(t *testing.T) {
	km := newECDHESPrivateKeyManager()

	t.Run("Test private key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidECDHESAESPrivateKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHESAESPrivateKeyFormat.Error(),
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

	flagTests := []struct {
		tcName    string
		curveType commonpb.EllipticCurveType
		ecPtFmt   commonpb.EcPointFormat
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "success private key manager NewKey() and NewKeyData()",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad curve",
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key template URL",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad dem key size",
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          composite.AESGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			c := tt.curveType
			encT := tt.encTmp
			ptFmt := tt.ecPtFmt

			privKeyProto := &ecdhespb.EcdhesAeadKeyFormat{
				Params: &ecdhespb.EcdhesAeadParams{
					KwParams: &ecdhespb.EcdhesKwParams{
						CurveType: c, // unknown curve type to force an error when calling km.Primitive()
					},
					EncParams: &ecdhespb.EcdhesAeadEncParams{
						AeadEnc: encT, // invalid data enc key template to force an error when calling km.Primitive()
					},
					EcPointFormat: ptFmt, // unknown EC Point format type to force an error when calling km.Primitive()
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
				require.Equal(t, kd.TypeUrl, ecdhesAESPrivateKeyTypeURL)
				require.Equal(t, kd.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
				return
			}

			if bytes.Equal(tt.encTmp.Value, badSerializedFormat) {
				require.EqualError(t, err, errInvalidECDHESAESPrivateKeyFormat.Error(),
					"ECDHESPrivate NewKey from serialized key with invalid serialized key")
				require.Empty(t, p)

				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}
