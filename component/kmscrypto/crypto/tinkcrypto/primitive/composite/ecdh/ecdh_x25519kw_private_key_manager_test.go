/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	cbcaead "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func TestECDHX25519XChachaPrivateKeyManager_Primitive(t *testing.T) {
	km := newX25519ECDHKWPrivateKeyManager()

	t.Run("Test private key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidx25519ECDHKWPrivateKey.Error(),
			"x25519ECDHKWPrivateKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test private key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidx25519ECDHKWPrivateKey.Error(),
			"x25519ECDHKWPrivateKeyManager primitive from bad serialized key must fail")
		require.Empty(t, p)
	})

	flagTests := []struct {
		tcName    string
		version   uint32
		curveType commonpb.EllipticCurveType
		keyType   ecdhpb.KeyType
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "private key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key type",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_UNKNOWN_KEY_TYPE,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "success private key manager Primitive()",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "success private key manager Primitive() with AES-CBC+HMAC encTmp",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    cbcaead.AES128CBCHMACSHA256KeyTemplate(),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			pub, pvt, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
			require.NoError(t, err)

			x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
			require.NoError(t, err)

			params := &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					KeyType:   tt.keyType,
					CurveType: tt.curveType,
				},
				EncParams: &ecdhpb.EcdhAeadEncParams{
					AeadEnc: tt.encTmp,
					CEK:     []byte{},
				},
				EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
			}

			privKeyProto := &ecdhpb.EcdhAeadPrivateKey{
				Version:  tt.version,
				KeyValue: x25519Pvt,
				PublicKey: &ecdhpb.EcdhAeadPublicKey{
					Version: x25519ECDHKWPrivateKeyVersion,
					Params:  params,
					X:       x25519Pub,
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

func TestECDHX25519XChachaPrivateKeyManager_DoesSupport(t *testing.T) {
	km := newX25519ECDHKWPrivateKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(x25519ECDHKWPrivateKeyTypeURL))
}

func TestECDHX25519XChachaPrivateKeyManager_NewKey(t *testing.T) {
	km := newX25519ECDHKWPrivateKeyManager()

	t.Run("Test private key manager NewKey() with nil key", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, errInvalidx25519ECDHKWPrivateKeyFormat.Error())
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKey() with bad serialize key", func(t *testing.T) {
		p, err := km.NewKey([]byte("bad.data"))
		require.EqualError(t, err, errInvalidx25519ECDHKWPrivateKeyFormat.Error(),
			"x25519ECDHKWPrivateKeyManager NewKey() from bad serialized key must fail")
		require.Empty(t, p)
	})

	flagTests := []struct {
		tcName    string
		curveType commonpb.EllipticCurveType
		keyType   ecdhpb.KeyType
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "success private key manager NewKey() and NewKeyData()",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad curve",
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key type",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_EC,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad key template URL",
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			privKeyProto := &ecdhpb.EcdhAeadKeyFormat{
				Params: &ecdhpb.EcdhAeadParams{
					KwParams: &ecdhpb.EcdhKwParams{
						CurveType: tt.curveType, // unknown curve to force an error when calling km.NewKey()
						KeyType:   tt.keyType,   // unknown key type to force an error when calling km.NewKey()
					},
					EncParams: &ecdhpb.EcdhAeadEncParams{
						AeadEnc: tt.encTmp, // invalid data enc key template to force an error when calling km.NewKey()
					},
					EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
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
				require.Equal(t, kd.TypeUrl, x25519ECDHKWPrivateKeyTypeURL)
				require.Equal(t, kd.KeyMaterialType, tinkpb.KeyData_ASYMMETRIC_PRIVATE)
				return
			}

			require.Errorf(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}
