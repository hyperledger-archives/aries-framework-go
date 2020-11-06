/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func TestPubKeyExport(t *testing.T) {
	flagTests := []struct {
		tcName      string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			tcName:      "export then read AES256GCM with ECDH P-256 public recipient key",
			keyTemplate: ecdh.ECDH256KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDHES P-384 public recipient key",
			keyTemplate: ecdh.ECDH384KWAES256GCMKeyTemplate(),
		},
		{
			tcName:      "export then read AES256GCM with ECDHES P-521 public recipient key",
			keyTemplate: ecdh.ECDH521KWAES256GCMKeyTemplate(),
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

			// now convert back ecPubKey to *keyset.Handle
			xPubKH, err := PublicKeyToKeysetHandle(ecPubKey)
			require.NoError(t, err)

			xk, err := ExtractPrimaryPublicKey(xPubKH)
			require.NoError(t, err)
			require.EqualValues(t, ecPubKey, xk)
		})
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

	t.Run("test buildCompositeKey() with bad curve", func(t *testing.T) {
		_, err := buildCompositeKey("", "", "BAD", nil, nil)
		require.EqualError(t, err, "undefined curve: unsupported curve")
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

		_, err = protoToCompositeKey(&tinkpb.KeyData{
			TypeUrl:         ecdhAESPublicKeyTypeURL,
			Value:           mKey,
			KeyMaterialType: 0,
		})
		require.EqualError(t, err, "undefined key type: 'UNKNOWN_KEY_TYPE'")
	})

	t.Run("test WriteEncrypted() should fail since it's not supported by Writer", func(t *testing.T) {
		kh, err := keyset.NewHandle(ecdh.ECDH256KWAES256GCMKeyTemplate())
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

		err = write(&failWriter{}, &tinkpb.Keyset{
			PrimaryKeyId: 0,
			Key: []*tinkpb.Keyset_Key{
				{
					KeyData: &tinkpb.KeyData{
						TypeUrl:         ecdhAESPublicKeyTypeURL,
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
		require.EqualError(t, err, "unexpected EOF")
	})

	t.Run("get undefined curve from getCurveProto should fail", func(t *testing.T) {
		_, err := getCurveProto("")
		require.EqualError(t, err, "unsupported curve")

		_, err = PublicKeyToKeysetHandle(&cryptoapi.PublicKey{
			Curve: "",
		})
		require.EqualError(t, err, "publicKeyToKeysetHandle: failed to convert curve string to proto: "+
			"unsupported curve")
	})
}

type failWriter struct {
}

func (w *failWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("failed to write")
}
