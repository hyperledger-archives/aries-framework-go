/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	tinkaead "github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func TestPubKeyExport(t *testing.T) {
	flagTests := []struct {
		tcName      string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			tcName:      "export then read ECDH KW NIST P-256 public recipient key",
			keyTemplate: ecdh.NISTP256ECDHKWKeyTemplate(),
		},
		{
			tcName:      "export then read ECDH KW NIST P-384 public recipient key",
			keyTemplate: ecdh.NISTP384ECDHKWKeyTemplate(),
		},
		{
			tcName:      "export then read ECDH KW NIST P-521 public recipient key",
			keyTemplate: ecdh.NISTP521ECDHKWKeyTemplate(),
		},
		{
			tcName:      "export then read ECDH KW X25519 public recipient key",
			keyTemplate: ecdh.X25519ECDHKWKeyTemplate(),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			kh, err := keyset.NewHandle(tt.keyTemplate)
			require.NoError(t, err)
			require.NotEmpty(t, kh)

			exportedKeyBytes := exportRawPublicKeyBytes(t, kh, false)
			require.NotEmpty(t, exportedKeyBytes)

			ecPubKey := new(cryptoapi.PublicKey)
			err = json.Unmarshal(exportedKeyBytes, ecPubKey)
			require.NoError(t, err)

			extractedPubKey, err := ExtractPrimaryPublicKey(kh)
			require.NoError(t, err)

			require.EqualValues(t, ecPubKey, extractedPubKey)

			// now convert back ecPubKey to *keyset.Handle using NISTP KW with default AES content encryption template
			xPubKH, err := PublicKeyToKeysetHandle(ecPubKey, ecdh.AES256GCM)
			require.NoError(t, err)

			// now convert back ecPubKey to *keyset.Handle using XChacha content encryption template
			x2PubKH, err := PublicKeyToKeysetHandle(ecPubKey, ecdh.XC20P)
			require.NoError(t, err)

			xk, err := ExtractPrimaryPublicKey(xPubKH)
			require.NoError(t, err)
			require.EqualValues(t, ecPubKey, xk)

			x2k, err := ExtractPrimaryPublicKey(x2PubKH)
			require.NoError(t, err)
			require.EqualValues(t, ecPubKey, x2k)
			if strings.Contains(tt.keyTemplate.TypeUrl, "X25519Kw") {
				require.EqualValues(t, x2k.Curve, commonpb.EllipticCurveType_CURVE25519.String())
				require.EqualValues(t, xk.Curve, commonpb.EllipticCurveType_CURVE25519.String())
			}

			t.Run("test PrivateKeyToKeysetHandle", func(t *testing.T) {
				testPrivateKeyAsKH(t, ecPubKey)
			})

			// now convert back ecPubKey to *keyset.Handle with CBC+HMAC content encryption.
			cbcHMACAlgs := []ecdh.AEADAlg{
				ecdh.AES128CBCHMACSHA256, ecdh.AES192CBCHMACSHA384, ecdh.AES256CBCHMACSHA384, ecdh.AES256CBCHMACSHA512,
			}

			for _, cbcAEAD := range cbcHMACAlgs {
				x3PubKH, err := PublicKeyToKeysetHandle(ecPubKey, cbcAEAD)
				require.NoError(t, err)

				xk, err = ExtractPrimaryPublicKey(x3PubKH)
				require.NoError(t, err)
				require.EqualValues(t, ecPubKey, xk)

				x3k, err := ExtractPrimaryPublicKey(x3PubKH)
				require.NoError(t, err)
				require.EqualValues(t, ecPubKey, x3k)
			}
		})
	}
}

func testPrivateKeyAsKH(t *testing.T, pubKey *cryptoapi.PublicKey) {
	var (
		crv        elliptic.Curve
		privECKey  *ecdsa.PrivateKey
		privKey    *cryptoapi.PrivateKey
		privOKPKey ed25519.PrivateKey
		pubKOPKey  ed25519.PublicKey
		err        error
	)

	privKey = &cryptoapi.PrivateKey{
		PublicKey: cryptoapi.PublicKey{
			Curve: pubKey.Curve,
			Type:  pubKey.Type,
		},
	}

	if pubKey.Type == "EC" {
		crv, err = subtle.GetCurve(pubKey.Curve)
		require.NoError(t, err)

		privECKey, err = ecdsa.GenerateKey(crv, rand.Reader)
		require.NoError(t, err)

		privKey.PublicKey.X = privECKey.PublicKey.X.Bytes()
		privKey.PublicKey.Y = privECKey.PublicKey.Y.Bytes()
		privKey.D = privECKey.D.Bytes()
	} else {
		pubKOPKey, privOKPKey, err = ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NotEmpty(t, pubKOPKey)
		require.NotEmpty(t, privKey)

		privKey.PublicKey.X = pubKOPKey
		privKey.D = privOKPKey
	}

	testPrivateKeyToKeySetHandle(t, privKey, ecdh.AES256GCM)
	testPrivateKeyToKeySetHandle(t, privKey, ecdh.XC20P)
	testPrivateKeyToKeySetHandle(t, privKey, ecdh.AES128CBCHMACSHA256)
}

func testPrivateKeyToKeySetHandle(t *testing.T, privKey *cryptoapi.PrivateKey, aeadAlg ecdh.AEADAlg) {
	pkh, err := PrivateKeyToKeysetHandle(privKey, aeadAlg)
	require.NoError(t, err)
	require.NotEmpty(t, pkh)

	if privKey.PublicKey.Type == "EC" {
		require.Equal(t, nistPECDHKWPrivateKeyTypeURL, pkh.KeysetInfo().KeyInfo[0].TypeUrl)
	} else {
		require.Equal(t, x25519ECDHKWPrivateKeyTypeURL, pkh.KeysetInfo().KeyInfo[0].TypeUrl)
	}
}

func exportRawPublicKeyBytes(t *testing.T, kh *keyset.Handle, expectError bool) []byte {
	t.Helper()

	pubKH, err := kh.Public()
	require.NoError(t, err)
	require.NotEmpty(t, pubKH)

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)

	if expectError {
		require.Error(t, err)
		return nil
	}

	require.NoError(t, err)
	require.NotEmpty(t, buf.Bytes())

	return buf.Bytes()
}

func TestNegativeCases(t *testing.T) {
	t.Run("test exportRawPublicKeyBytes() with an unsupported key template", func(t *testing.T) {
		kh, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
		require.NoError(t, err)

		exportedKeyBytes := exportRawPublicKeyBytes(t, kh, true)
		require.Empty(t, exportedKeyBytes)
	})

	t.Run("test buildCompositeKey() with bad EC curve", func(t *testing.T) {
		_, _, err := buildCompositeKey("", ecdhpb.KeyType_EC.String(), "BAD", nil, nil)
		require.EqualError(t, err, "undefined EC curve: unsupported curve")
	})

	t.Run("test buildCompositeKey() with bad OKP curve", func(t *testing.T) {
		_, _, err := buildCompositeKey("", ecdhpb.KeyType_OKP.String(), "BAD", nil, nil)
		require.EqualError(t, err, "invalid OKP curve: BAD")
	})

	t.Run("test protoToCompositeKey() with bad key type", func(t *testing.T) {
		mKey, err := proto.Marshal(&ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params: &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					CurveType: commonpb.EllipticCurveType_NIST_P256,
					KeyType:   ecdhpb.KeyType_UNKNOWN_KEY_TYPE, // Unknown key type should trigger failure
				},
				EncParams:     nil,
				EcPointFormat: 0,
			},
			KID: "0123",
			X:   nil,
			Y:   nil,
		})
		require.NoError(t, err)

		_, _, err = protoToCompositeKey(&tinkpb.KeyData{
			TypeUrl:         nistPECDHKWPublicKeyTypeURL,
			Value:           mKey,
			KeyMaterialType: 0,
		})
		require.EqualError(t, err, "invalid keyType: UNKNOWN_KEY_TYPE")
	})

	t.Run("test WriteEncrypted() should fail since it's not supported by Writer", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)
		require.NotEmpty(t, kh)

		pubKH, err := kh.Public()
		require.NoError(t, err)
		require.NotEmpty(t, pubKH)

		buf := new(bytes.Buffer)
		pubKeyWriter := NewWriter(buf)
		require.NotEmpty(t, pubKeyWriter)

		err = pubKeyWriter.WriteEncrypted(nil)
		require.Error(t, err)
	})

	t.Run("test write() should fail with empty key set", func(t *testing.T) {
		buf := new(bytes.Buffer)

		pw := &PubKeyWriter{w: buf}
		err := pw.write(&tinkpb.Keyset{})
		require.Error(t, err)
	})

	t.Run("test write() should fail with failing writer", func(t *testing.T) {
		mKey, err := proto.Marshal(&ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params: &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					CurveType: commonpb.EllipticCurveType_NIST_P256,
					KeyType:   ecdhpb.KeyType_EC,
				},
				EncParams:     nil,
				EcPointFormat: 0,
			},
			KID: "0123",
			X:   nil,
			Y:   nil,
		})
		require.NoError(t, err)

		pw := &PubKeyWriter{w: &failWriter{}}
		err = pw.write(&tinkpb.Keyset{
			PrimaryKeyId: 0,
			Key: []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         nistPECDHKWPublicKeyTypeURL,
						Value:           mKey,
						KeyMaterialType: 0,
					},
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            0,
					OutputPrefixType: 0,
				},
			},
		})
		require.EqualError(t, err, "failed to write")
	})

	t.Run("call newECDHKey() with bad marshalled bytes", func(t *testing.T) {
		_, err := newECDHKey([]byte("bad data"))
		require.Contains(t, err.Error(), "cannot parse invalid wire-format data")
	})

	t.Run("get undefined curve from getCurveProto should fail", func(t *testing.T) {
		_, err := getCurveProto("")
		require.EqualError(t, err, "unsupported curve")

		_, err = PublicKeyToKeysetHandle(&cryptoapi.PublicKey{
			Curve: "",
		}, ecdh.AES256GCM)
		require.EqualError(t, err, "publicKeyToKeysetHandle: failed to convert curve string to proto: "+
			"unsupported curve")
	})

	t.Run("PublicKeyToKeysetHandle using pubKey with bad keyType", func(t *testing.T) {
		_, err := PublicKeyToKeysetHandle(&cryptoapi.PublicKey{
			Curve: elliptic.P256().Params().Name,
		}, ecdh.AES256GCM)
		require.EqualError(t, err, "publicKeyToKeysetHandle: failed to convert key type to proto: unsupported key type")
	})

	t.Run("PublicKeyToKeysetHandle with valid key and bad AEADAlg", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
		require.NoError(t, err)
		require.NotEmpty(t, kh)

		exportedKeyBytes := exportRawPublicKeyBytes(t, kh, false)
		require.NotEmpty(t, exportedKeyBytes)

		ecPubKey := new(cryptoapi.PublicKey)
		err = json.Unmarshal(exportedKeyBytes, ecPubKey)
		require.NoError(t, err)

		_, err = PublicKeyToKeysetHandle(ecPubKey, -1)
		require.EqualError(t, err, "publicKeyToKeysetHandle: invalid encryption algorithm: ''")
	})

	t.Run("ExtractPrimaryPublicKey using an invalid (symmetric key)", func(t *testing.T) {
		kt := tinkaead.AES128CTRHMACSHA256KeyTemplate()
		badKH, err := keyset.NewHandle(kt)
		require.NoError(t, err)

		_, err = ExtractPrimaryPublicKey(badKH)
		require.EqualError(t, err, "extractPrimaryPublicKey: failed to get public key content: exporting "+
			"unencrypted secret key material is forbidden")
	})

	t.Run("keyTemplateAndURL with invalid curve", func(t *testing.T) {
		_, _, err := keyTemplateAndURL(commonpb.EllipticCurveType_UNKNOWN_CURVE, ecdh.AES256GCM, true)
		require.EqualError(t, err, "invalid key curve: 'UNKNOWN_CURVE'")

		_, _, err = keyTemplateAndURL(commonpb.EllipticCurveType_UNKNOWN_CURVE, ecdh.AES256GCM, false)
		require.EqualError(t, err, "invalid key curve: 'UNKNOWN_CURVE'")
	})
}

type failWriter struct{}

func (w *failWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("failed to write")
}
