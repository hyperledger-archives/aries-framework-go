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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

func TestECDHX25519AESPublicKeyManager_Primitive(t *testing.T) {
	km := newECDHX25519AESPublicKeyManager()

	t.Run("Test public key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidECDHX25519AESPublicKey.Error(),
			"ecdhX25519AESPublicKeyManager primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test public key manager Primitive() with bad serialize key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidECDHX25519AESPublicKey.Error(),
			"ecdhX25519AESPublicKeyManager primitive from bad serialized key must fail")
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
		keyType   ecdhpb.KeyType
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "public key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "private key manager NewKey() and NewKeyData() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad key type",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_EC,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "success public key manager Primitive()",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp:    aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
			keyType:   ecdhpb.KeyType_OKP,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "public key manager Primitive() using key with bad content encryption key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_CURVE25519,
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
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
			require.NoError(t, err)

			pubKeyProto := &ecdhpb.EcdhAeadPublicKey{
				Version: tt.version, // if version > 0  to force an error when calling km.Primitive()
				Params: &ecdhpb.EcdhAeadParams{
					KwParams: &ecdhpb.EcdhKwParams{
						CurveType: tt.curveType, // unknown curve to force an error when calling km.NewKey()
						KeyType:   tt.keyType,   // invalid key type to force error when calling km.Primitive()
					},
					EncParams: &ecdhpb.EcdhAeadEncParams{
						AeadEnc: tt.encTmp, // invalid data enc key template to force error when calling km.Primitive()
						CEK:     []byte{},
					},
					EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
				},
				X: x25519Pub,
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			if strings.Contains(tt.tcName, "with bad content encryption key size") {
				require.EqualError(t, err, errInvalidECDHX25519AESPublicKey.Error(),
					"ecdhX25519AESPublicKeyManager primitive from serialized key with invalid serialized key")
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

func TestEcdhX25519AESPublicKeyManager_DoesSupport(t *testing.T) {
	km := newECDHX25519AESPublicKeyManager()
	require.False(t, km.DoesSupport("bad/url"))
	require.True(t, km.DoesSupport(ecdhX25519AESPublicKeyTypeURL))
}

func TestEcdhX25519AESPublicKeyManager_NewKeyAndNewKeyData(t *testing.T) {
	km := newECDHX25519AESPublicKeyManager()

	t.Run("Test public key manager NewKey()", func(t *testing.T) {
		k, err := km.NewKey(nil)
		require.EqualError(t, err, "ecdh_x25519kw_aesaead_public_key_manager: NewKey not implemented")
		require.Empty(t, k)
	})

	t.Run("Test private key manager NewKeyData()", func(t *testing.T) {
		p, err := km.NewKeyData(nil)
		require.EqualError(t, err, "ecdh_x25519kw_aesaead_public_key_manager: NewKeyData not implemented")
		require.Empty(t, p)
	})
}
