/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"
)

func TestPubKeyExportAndRead(t *testing.T) {
	p256DERTemplate, err := getKeyTemplate(kms.ECDSAP256TypeDER)
	require.NoError(t, err)

	p384DERTemplate, err := getKeyTemplate(kms.ECDSAP384TypeDER)
	require.NoError(t, err)

	p521DERTemplate, err := getKeyTemplate(kms.ECDSAP521TypeDER)
	require.NoError(t, err)

	flagTests := []struct {
		tcName      string
		keyType     kms.KeyType
		keyTemplate *tinkpb.KeyTemplate
		doSign      bool
	}{
		{
			tcName:      "export then read ECDSAP256DER public key",
			keyType:     kms.ECDSAP256TypeDER,
			keyTemplate: p256DERTemplate,
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP384DER public key",
			keyType:     kms.ECDSAP384TypeDER,
			keyTemplate: p384DERTemplate,
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP521DER public key",
			keyType:     kms.ECDSAP521TypeDER,
			keyTemplate: p521DERTemplate,
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP256IEEEP1363 public key",
			keyType:     kms.ECDSAP256TypeIEEEP1363,
			keyTemplate: createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256),
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP384IEEEP1363 public key",
			keyType:     kms.ECDSAP384TypeIEEEP1363,
			keyTemplate: createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA384, commonpb.EllipticCurveType_NIST_P384),
			doSign:      true,
		},
		{
			tcName:      "export then read ECDSAP521IEEEP1363 public key",
			keyType:     kms.ECDSAP521TypeIEEEP1363,
			keyTemplate: createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA512, commonpb.EllipticCurveType_NIST_P521),
			doSign:      true,
		},
		{
			tcName:      "export then read ED25519 public key",
			keyType:     kms.ED25519Type,
			keyTemplate: signature.ED25519KeyWithoutPrefixTemplate(),
			doSign:      true,
		},
		{
			tcName:      "export then read BBS+ BLS12381G2 public key",
			keyType:     kms.BLS12381G2Type,
			keyTemplate: bbs.BLS12381G2KeyTemplate(),
			doSign:      true,
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run(tt.tcName, func(t *testing.T) {
			exportedKeyBytes, origKH := exportRawPublicKeyBytes(t, tt.keyTemplate, false)

			kh, err := PublicKeyBytesToHandle(exportedKeyBytes, tt.keyType)
			require.NoError(t, err)
			require.NotEmpty(t, kh)

			if tt.doSign {
				if tt.keyType == kms.BLS12381G2Type {
					msg1 := []byte("Lorem ipsum dolor sit amet,")
					msg2 := []byte("consectetur adipiscing elit.")
					msg := [][]byte{msg1, msg2}
					signer, err := bbs.NewSigner(origKH)
					require.NoError(t, err)
					require.NotEmpty(t, signer)

					s, err := signer.Sign(msg)
					require.NoError(t, err)
					require.NotEmpty(t, s)

					verifier, err := bbs.NewVerifier(kh)
					require.NoError(t, err)
					require.NotEmpty(t, verifier)

					err = verifier.Verify(msg, s)
					require.NoError(t, err)

					nonce := []byte("somenonce")
					proof, err := verifier.DeriveProof(msg, s, nonce, []int{1})
					require.NoError(t, err)
					require.NotEmpty(t, proof)

					err = verifier.VerifyProof([][]byte{msg2}, proof, nonce)
					require.NoError(t, err)

					return
				}
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
				require.NoError(t, err)
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
		kh, err := PublicKeyBytesToHandle([]byte{}, kms.ECDSAP256TypeIEEEP1363)
		require.EqualError(t, err, "pubKey is empty")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with empty KeyType", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, "")
		require.EqualError(t, err, "error getting marshalled proto key: invalid key type")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP256TypeDER", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP256TypeDER)
		require.EqualError(t, err, "error getting marshalled proto key: asn1: syntax error: truncated tag or length")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP256TypeIEEEP1363", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP256TypeIEEEP1363)
		require.EqualError(t, err, "error getting marshalled proto key: failed to unamrshal public ecdsa key")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP384TypeDER", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP384TypeDER)
		require.EqualError(t, err, "error getting marshalled proto key: asn1: syntax error: truncated tag or length")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP384TypeIEEEP1363", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP384TypeIEEEP1363)
		require.EqualError(t, err, "error getting marshalled proto key: failed to unamrshal public ecdsa key")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP521TypeDER", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP521TypeDER)
		require.EqualError(t, err, "error getting marshalled proto key: asn1: syntax error: truncated tag or length")
		require.Empty(t, kh)
	})

	t.Run("test publicKeyBytesToHandle with bad pubKey and ECDSAP521TypeIEEEP1363", func(t *testing.T) {
		kh, err := PublicKeyBytesToHandle([]byte{1}, kms.ECDSAP521TypeIEEEP1363)
		require.EqualError(t, err, "error getting marshalled proto key: failed to unamrshal public ecdsa key")
		require.Empty(t, kh)
	})

	t.Run("test getMarshalledECDSAKey with empty curveName", func(t *testing.T) {
		kh, err := getMarshalledECDSADERKey([]byte{},
			"",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		require.EqualError(t, err, "undefined curve")
		require.Empty(t, kh)
	})

	t.Run("test getMarshalledECDSAKey with empty curveName", func(t *testing.T) {
		kh, err := getMarshalledECDSAIEEEP1363Key([]byte{},
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

	t.Run("test export with symmetric key should fail", func(t *testing.T) {
		kt := aead.AES256GCMKeyTemplate()
		kh, err := keyset.NewHandle(kt)
		require.NoError(t, err)
		require.NotEmpty(t, kh)

		buf := new(bytes.Buffer)
		pubKeyWriter := NewWriter(buf)
		require.NotEmpty(t, pubKeyWriter)

		err = kh.Write(pubKeyWriter, &NoLockMock{})
		require.Error(t, err)
		require.Empty(t, buf.Bytes())
	})
}

// NoLockMock is a mock lock service that does no encryption/decryption of plaintext and implements tink.AEAD interface.
type NoLockMock struct{}

// Encrypt is a mock function of AEAD.Encrypt().
func (s *NoLockMock) Encrypt(pt, aad []byte) ([]byte, error) {
	return pt, nil
}

// Decrypt is a mock function of AEAD.Decrypt().
func (s *NoLockMock) Decrypt(req, aad []byte) ([]byte, error) {
	return req, nil
}
