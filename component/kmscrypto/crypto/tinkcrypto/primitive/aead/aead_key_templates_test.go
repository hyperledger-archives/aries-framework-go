/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead_test

import (
	"bytes"
	"testing"

	tinkaead "github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
)

func TestKeyTemplates(t *testing.T) {
	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AEAD_AES_128_CBC_HMAC_SHA_256",
			template: aead.AES128CBCHMACSHA256KeyTemplate(),
		}, {
			name:     "AEAD_AES_192_CBC_HMAC_SHA_384",
			template: aead.AES192CBCHMACSHA384KeyTemplate(),
		}, {
			name:     "AEAD_AES_256_CBC_HMAC_SHA_384",
			template: aead.AES256CBCHMACSHA384KeyTemplate(),
		}, {
			name:     "AEAD_AES_256_CBC_HMAC_SHA_512",
			template: aead.AES256CBCHMACSHA512KeyTemplate(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			testEncryptDecrypt(t, kh)
		})
	}
}

func testEncryptDecrypt(t *testing.T, kh *keyset.Handle) {
	t.Helper()

	primitive, err := tinkaead.New(kh)
	require.NoError(t, err, "aead.New(handle) failed")

	testInputs := []struct {
		plaintext []byte
		aad1      []byte
		aad2      []byte
	}{
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte(""),
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: nil,
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		}, {
			plaintext: nil,
			aad1:      []byte(""),
			aad2:      []byte(""),
		}, {
			plaintext: nil,
			aad1:      nil,
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      nil,
		}, {
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      []byte(""),
		},
	}

	for _, ti := range testInputs {
		ciphertext, err := primitive.Encrypt(ti.plaintext, ti.aad1)
		require.NoError(t, err, "encryption failed")

		decrypted, err := primitive.Decrypt(ciphertext, ti.aad2)
		require.NoError(t, err, "decryption failed")

		// must use bytes.Equal() instead of require.EqualValues() which errors out when ti.plaintext = []byte(nil)
		// and decrypted = []byte{}.
		if !bytes.Equal(ti.plaintext, decrypted) {
			t.Fatalf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, ti.plaintext)
		}
	}
}
