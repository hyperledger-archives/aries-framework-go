/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"bytes"
	"errors"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh1pu"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	commoncompb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

func TestPubKeyExport(t *testing.T) {
	var flagTests = []struct {
		tcName      string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			tcName:      "export then read AES256GCM with ECDHES P-256 public key",
			keyTemplate: ecdhes.ECDHES256KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDH1PU P-256 public key",
			keyTemplate: ecdh1pu.ECDH1PU256KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDHES P-384 public key",
			keyTemplate: ecdhes.ECDHES384KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDH1PU P-384 public key",
			keyTemplate: ecdh1pu.ECDH1PU384KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDHES P-521 public key",
			keyTemplate: ecdhes.ECDHES521KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDH1PU P-521 public key",
			keyTemplate: ecdh1pu.ECDH1PU521KWAES256GCMKeyTemplate(),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			exportedKeyBytes := exportRawPublicKeyBytes(t, tt.keyTemplate, false)
			require.NotEmpty(t, exportedKeyBytes)
		})
	}
}

func exportRawPublicKeyBytes(t *testing.T, keyTemplate *tinkpb.KeyTemplate, expectError bool) []byte {
	t.Helper()

	kh, err := keyset.NewHandle(keyTemplate)
	require.NoError(t, err)
	require.NotEmpty(t, kh)

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
		exportedKeyBytes := exportRawPublicKeyBytes(t, hybrid.ECIESHKDFAES128GCMKeyTemplate(), true)
		require.Empty(t, exportedKeyBytes)
	})

	t.Run("test buildCompositeKey() with bad curve", func(t *testing.T) {
		_, err := buildCompositeKey("", "", "BAD", nil, nil)
		require.EqualError(t, err, "undefined curve: unsupported curve")
	})

	t.Run("test protoToCompositeKey() with bad key type", func(t *testing.T) {
		mKey, err := proto.Marshal(&ecdhespb.EcdhesAeadPublicKey{
			Version: 0,
			Params: &ecdhespb.EcdhesAeadParams{
				KwParams: &ecdhespb.EcdhesKwParams{
					CurveType:  commonpb.EllipticCurveType_NIST_P256,
					KeyType:    commoncompb.KeyType_UNKNOWN_KEY_TYPE, // Unknown key type should trigger failure
					Recipients: nil,
				},
				EncParams:     nil,
				EcPointFormat: 0,
			},
			KID: "0123",
			X:   nil,
			Y:   nil,
		})
		require.NoError(t, err)

		_, err = protoToCompositeKey(&tinkpb.KeyData{
			TypeUrl:         ecdhesAESPublicKeyTypeURL,
			Value:           mKey,
			KeyMaterialType: 0,
		})
		require.EqualError(t, err, "undefined key type: 'UNKNOWN_KEY_TYPE'")

		_, err = protoToCompositeKey(&tinkpb.KeyData{
			TypeUrl:         ecdh1puAESPublicKeyTypeURL,
			Value:           mKey,
			KeyMaterialType: 0,
		})
		require.EqualError(t, err, "undefined key type: 'UNKNOWN_KEY_TYPE'")
	})

	t.Run("test WriteEncrypted() should fail since it's not supported by Writer", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
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

		err := write(buf, &tinkpb.Keyset{})
		require.Error(t, err)
	})

	t.Run("test write() should fail with failing writer", func(t *testing.T) {
		mKey, err := proto.Marshal(&ecdhespb.EcdhesAeadPublicKey{
			Version: 0,
			Params: &ecdhespb.EcdhesAeadParams{
				KwParams: &ecdhespb.EcdhesKwParams{
					CurveType:  commonpb.EllipticCurveType_NIST_P256,
					KeyType:    commoncompb.KeyType_EC,
					Recipients: nil,
				},
				EncParams:     nil,
				EcPointFormat: 0,
			},
			KID: "0123",
			X:   nil,
			Y:   nil,
		})
		require.NoError(t, err)

		err = write(&failWriter{}, &tinkpb.Keyset{
			PrimaryKeyId: 0,
			Key: []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         ecdhesAESPublicKeyTypeURL,
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
}

type failWriter struct {
}

func (w *failWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("failed to write")
}
