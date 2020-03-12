/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestPubKeyExportAndRead(t *testing.T) {
	var flagTests = []struct {
		tcName      string
		keyType     kms.KeyType
		keyTemplate *tinkpb.KeyTemplate
		doSign      bool
	}{
		{
			tcName:      "export then read ECDSAP256 public key",
			keyType:     kms.ECDSAP256Type,
			keyTemplate: signature.ECDSAP256KeyTemplate(),
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP384 public key",
			keyType:     kms.ECDSAP384Type,
			keyTemplate: signature.ECDSAP384KeyTemplate(),
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP521 public key",
			keyType:     kms.ECDSAP521Type,
			keyTemplate: signature.ECDSAP521KeyTemplate(),
			doSign:      true,
		},
		{
			tcName:      "export then read ED25519 public key",
			keyType:     kms.Ed25519Type,
			keyTemplate: signature.ED25519KeyTemplate(),
			doSign:      true,
		},
	}

	// nolint:scopelint
	for _, tt := range flagTests {
		t.Run(tt.tcName, func(t *testing.T) {
			exportedKeyBytes, origKH := exportRawPublicKeyBytes(t, tt.keyTemplate, false)

			kh, err := publicKeyBytesToHandle(exportedKeyBytes, tt.keyType)
			require.NoError(t, err)
			require.NotEmpty(t, kh)

			if tt.doSign {
				// test signing with origKH then verifying with kh read from exported public key
				msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
				signer, err := signature.NewSigner(origKH)
				require.NoError(t, err)
				require.NotEmpty(t, signer)

				s, err := signer.Sign(msg)
				require.NoError(t, err)
				require.NotEmpty(t, s)

				verifier, err := signature.NewVerifier(kh)
				require.NoError(t, err)
				require.NotEmpty(t, verifier)

				err = verifier.Verify(s, msg)
				require.NotEmpty(t, err)
			}
		})
	}
}

func exportRawPublicKeyBytes(t *testing.T, keyTemplate *tinkpb.KeyTemplate, expectError bool) ([]byte, *keyset.Handle) {
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
		return nil, kh
	}

	require.NoError(t, err)
	require.NotEmpty(t, buf.Bytes())

	return buf.Bytes(), kh
}

func TestNegativeCases(t *testing.T) {
	t.Run("test publicKeyBytesToHandle with empty pubKey", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{}, kms.ECDSAP256Type)
		require.EqualError(t, err, "pubKey is empty")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with empty KeyType", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{1}, "")
		require.EqualError(t, err, "error getting marshalled proto key: invalid key type")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP256Type", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{1}, kms.ECDSAP256Type)
		require.EqualError(t, err, "error getting marshalled proto key: invalid key")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP384Type", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{1}, kms.ECDSAP384Type)
		require.EqualError(t, err, "error getting marshalled proto key: invalid key")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP521Type", func(t *testing.T) {
		kh, err := publicKeyBytesToHandle([]byte{1}, kms.ECDSAP521Type)
		require.EqualError(t, err, "error getting marshalled proto key: invalid key")
		require.Empty(t, kh)
	})

	t.Run("test getMarshalledECDSAKey with empty curveName", func(t *testing.T) {
		kh, err := getMarshalledECDSAKey([]byte{},
			"",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		require.EqualError(t, err, "undefined curve")
		require.Empty(t, kh)
	})

	t.Run("test exportRawPublicKeyBytes with an unsupported key template", func(t *testing.T) {
		exportedKeyBytes, _ := exportRawPublicKeyBytes(t, hybrid.ECIESHKDFAES128GCMKeyTemplate(), true)
		require.Empty(t, exportedKeyBytes)
	})
}
