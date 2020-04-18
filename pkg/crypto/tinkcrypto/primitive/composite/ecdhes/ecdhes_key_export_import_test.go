/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"
)

func TestPubKeyExportAndRead(t *testing.T) {
	var flagTests = []struct {
		tcName      string
		keyTemplate *tinkpb.KeyTemplate
	}{
		{
			tcName:      "export then read AES256GCM with ECDHES public key",
			keyTemplate: ECDHES256KWAES256GCMKeyTemplate(),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			exportedKeyBytes := exportRawPublicKeyBytes(t, tt.keyTemplate, false)

			kh, err := publicKeyBytesToHandle(exportedKeyBytes)
			require.NoError(t, err)
			require.NotEmpty(t, kh)
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
	t.Run("test publicKeyBytesToHandle with empty pubKey", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{})
		require.EqualError(t, err, "pubKey is empty")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP256Type", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{1})
		require.Contains(t, err.Error(), "error getting marshalled proto key: invalid character")
		require.Empty(t, kh)
	})

	t.Run("test exportRawPublicKeyBytes with an unsupported key template", func(t *testing.T) {
		exportedKeyBytes := exportRawPublicKeyBytes(t, hybrid.ECIESHKDFAES128GCMKeyTemplate(), true)
		require.Empty(t, exportedKeyBytes)
	})

	t.Run("test WriteEncrypted() should fail since it's not supported by Writer", func(t *testing.T) {
		kh, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
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
}
