/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
)

func TestECDHESKeyTemplateSuccess(t *testing.T) {
	flagTests := []struct {
		tcName   string
		tmplFunc func() *tinkpb.KeyTemplate
	}{
		{
			tcName:   "create ECDH NIST P-256 KW with AES256-GCM key templates test",
			tmplFunc: ECDH256KWAES256GCMKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES256-GCM key templates test",
			tmplFunc: ECDH384KWAES256GCMKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES256-GCM key templates test",
			tmplFunc: ECDH521KWAES256GCMKeyTemplate,
		},
		{
			tcName:   "creat ECDH X25519 KW with XChacha20Poly1305 key templates test",
			tmplFunc: X25519XChachaECDHKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with XChacha20Poly1305 key templates test",
			tmplFunc: ECDH256KWXChachaKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-384 KW XChacha20Poly1305 key templates test",
			tmplFunc: ECDH384KWXChachaKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-521 KW key XChacha20Poly1305 templates test",
			tmplFunc: ECDH521KWXChachaKeyTemplate,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES256-GCM key templates test",
			tmplFunc: X25519AES256GCMECDHKeyTemplate,
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			cek := random.GetRandomBytes(uint32(32))

			kt := tc.tmplFunc()

			kh, err := keyset.NewHandle(kt)
			require.NoError(t, err)

			pubKH, err := kh.Public()
			require.NoError(t, err)

			e, err := NewECDHEncrypt(pubKH)
			require.NoError(t, err)

			pt := []byte("secret message")
			aad := []byte("aad message")

			// trying to encrypt using the above KH should fail since cek was not set
			ct, err := e.Encrypt(pt, aad)
			require.Error(t, err)
			require.Empty(t, ct)

			// now try to create a new KH for primitive execution and try to encrypt
			if strings.Contains(tc.tcName, "XChacha") {
				kt = XChachaKeyTemplateWithCEK(cek)
			} else {
				kt = AES256GCMKeyTemplateWithCEK(cek)
			}

			kh, err = keyset.NewHandle(kt)
			require.NoError(t, err)

			pubKH, err = kh.Public()
			require.NoError(t, err)

			e, err = NewECDHEncrypt(pubKH)
			require.NoError(t, err)

			ct, err = e.Encrypt(pt, aad)
			require.NoError(t, err)
			require.NotEmpty(t, ct)

			// decrypt with kh that has cek
			d, er := NewECDHDecrypt(kh)
			require.NoError(t, er)

			dpt, er := d.Decrypt(ct, aad)
			require.NoError(t, er)
			require.Equal(t, pt, dpt)
		})
	}
}
