/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/stretchr/testify/require"

	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
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

	recipients := generateRecipients(t)

	badRecipients := generateBadRecipients(t)

	var flagTests = []struct {
		tcName     string
		version    uint32
		curveType  commonpb.EllipticCurveType
		ecPtFmt    commonpb.EcPointFormat
		encTmp     *tinkpb.KeyTemplate
		recipients []*ecdhespb.EcdhesAeadRecipientPublicKey
	}{
		{
			tcName:     "public key manager Primitive() using key with bad version",
			version:    9999,
			curveType:  commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:    commonpb.EcPointFormat_COMPRESSED,
			encTmp:     aead.AES128GCMKeyTemplate(),
			recipients: recipients,
		},
		{
			tcName:     "public key manager Primitive() using key with bad curve",
			version:    0,
			curveType:  commonpb.EllipticCurveType_UNKNOWN_CURVE,
			ecPtFmt:    commonpb.EcPointFormat_COMPRESSED,
			encTmp:     aead.AES128GCMKeyTemplate(),
			recipients: recipients,
		},
		{
			tcName:     "success public key manager Primitive()",
			version:    0,
			curveType:  commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:    commonpb.EcPointFormat_UNCOMPRESSED,
			encTmp:     aead.AES128GCMKeyTemplate(),
			recipients: recipients,
		},
		{
			tcName:    "public key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
			recipients: recipients,
		},
		{
			tcName:    "public key manager Primitive() using key with bad content encryption key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          aesGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
			recipients: recipients,
		},
		{
			tcName:     "public key manager Primitive() with bad recipients keys",
			version:    0,
			curveType:  commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:    commonpb.EcPointFormat_UNCOMPRESSED,
			encTmp:     aead.AES128GCMKeyTemplate(),
			recipients: badRecipients,
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			c := tt.curveType
			encT := tt.encTmp
			ptFmt := tt.ecPtFmt
			v := tt.version
			recipientsKeys := tt.recipients

			// temporarily reset curvType if its unknown type so subtle.GetCurve() below doesn't fail
			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = commonpb.EllipticCurveType_NIST_P256
			}

			crv, err := hybrid.GetCurve(c.String())
			require.NoError(t, err)
			_, x, y, err := elliptic.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			// set back curvType if it was unknown to proceed with the test
			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = tt.curveType
			}

			pubKeyProto := &ecdhespb.EcdhesAeadPublicKey{
				Version: v, // if v > 0  to force an error when calling km.Primitive()
				Params: &ecdhespb.EcdhesAeadParams{
					KwParams: &ecdhespb.EcdhesKwParams{
						CurveType:  c, // unknown curve type to force an error when calling km.Primitive()
						Recipients: recipientsKeys,
					},
					EncParams: &ecdhespb.EcdhesAeadEncParams{
						AeadEnc: encT, // invalid data enc key template to force an error when calling km.Primitive()
					},
					EcPointFormat: ptFmt, // unknown EC Pint format type to force an error when calling km.Primitive()
				},
				X: x.Bytes(),
				Y: y.Bytes(),
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			if strings.Contains(tt.tcName, "with bad content encryption key size") {
				require.EqualError(t, err, errInvalidECDHESPublicKey.Error(),
					"ECDHESPublic primitive from serialized key with invalid serialized key")
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

func generateBadRecipients(t *testing.T) []*ecdhespb.EcdhesAeadRecipientPublicKey {
	recipients := generateRecipients(t)

	for _, rec := range recipients {
		rec.Version = 999
	}

	return recipients
}

func generateRecipients(t *testing.T) []*ecdhespb.EcdhesAeadRecipientPublicKey {
	t.Helper()

	curvProto := commonpb.EllipticCurveType_NIST_P256
	curve, err := hybrid.GetCurve(curvProto.String())
	require.NoError(t, err)

	recipient1Priv, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	recipient2Priv, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	recipient3Priv, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	return []*ecdhespb.EcdhesAeadRecipientPublicKey{
		{
			Version:   0,
			CurveType: curvProto,
			X:         recipient1Priv.PublicKey.Point.X.Bytes(),
			Y:         recipient1Priv.PublicKey.Point.Y.Bytes(),
		},
		{
			Version:   0,
			CurveType: curvProto,
			X:         recipient2Priv.PublicKey.Point.X.Bytes(),
			Y:         recipient2Priv.PublicKey.Point.Y.Bytes(),
		},
		{
			Version:   0,
			CurveType: curvProto,
			X:         recipient3Priv.PublicKey.Point.X.Bytes(),
			Y:         recipient3Priv.PublicKey.Point.Y.Bytes(),
		},
	}
}

func TestEcdhesPublicKeyManager_DoesSupport(t *testing.T) {
	km := newECDHESPublicKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhesPublicKeyTypeURL))
}

func TestEcdhesPublicKeyManager_NewKeyAndNewKeyData(t *testing.T) {
	km := newECDHESPublicKeyManager()

	t.Run("Test public key manager NewKey()", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, "ecdhes_public_key_manager: NewKey not implemented")
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKeyData()", func(t *testing.T) {
		p, err := km.NewKeyData(nil)
		require.EqualError(t, err, "ecdhes_public_key_manager: NewKeyData not implemented")
		require.Empty(t, p)
	})
}
