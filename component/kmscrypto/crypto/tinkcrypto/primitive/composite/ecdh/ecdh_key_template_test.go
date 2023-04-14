/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"testing"
	"time"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

func TestECDHESKeyTemplateSuccess(t *testing.T) {
	flagTests := []struct {
		tcName   string
		tmplFunc func() *tinkpb.KeyTemplate
		nistpKW  bool
		encAlg   AEADAlg
	}{
		{
			tcName:   "create ECDH NIST P-256 KW with AES256-GCM key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256GCM,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES256-GCM key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256GCM,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES256-GCM key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256GCM,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES256-GCM key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   AES256GCM,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with XChacha20Poly1305 key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   XC20P,
		},
		{
			tcName:   "create ECDH NIST P-384 KW XChacha20Poly1305 key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   XC20P,
		},
		{
			tcName:   "create ECDH NIST P-521 KW XChacha20Poly1305 key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   XC20P,
		},
		{
			tcName:   "creat ECDH X25519 KW with XChacha20Poly1305 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   XC20P,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with AES128-CBC+HMAC-SHA256 key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES128CBCHMACSHA256,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES128-CBC+HMAC-SHA256 key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES128CBCHMACSHA256,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES128-CBC+HMAC-SHA256 key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES128CBCHMACSHA256,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES128-CBC+HMAC-SHA256 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   AES128CBCHMACSHA256,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with AES192-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES192CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES192-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES192CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES192-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES192CBCHMACSHA384,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES192-CBC+HMAC-SHA384 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   AES192CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with AES256-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES256-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES256-CBC+HMAC-SHA384 key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA384,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES256-CBC+HMAC-SHA384 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   AES256CBCHMACSHA384,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with AES256-CBC+HMAC-SHA512 key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA512,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES256-CBC+HMAC-SHA512 key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA512,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES256-CBC+HMAC-SHA512 key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			nistpKW:  true,
			encAlg:   AES256CBCHMACSHA512,
		},
		{
			tcName:   "creat ECDH X25519 KW with AES256-CBC+HMAC-SHA512 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			encAlg:   AES256CBCHMACSHA512,
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			cek := createCEK(tc.encAlg)
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

			elapsed := time.Now()

			// now try to create a new KH for primitive execution and try to encrypt
			kt = KeyTemplateForECDHPrimitiveWithCEK(cek, tc.nistpKW, tc.encAlg)

			t.Logf("time spent in ECDH keyTemplateWithCEK: %s", time.Since(elapsed))

			kh, err = keyset.NewHandle(kt)
			require.NoError(t, err)

			t.Logf("time spent in ECDH keyTemplateWithCEK + NewHandle(): %s", time.Since(elapsed))

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

func createCEK(cbcAlg AEADAlg) []byte {
	switch cbcAlg {
	case AES128CBCHMACSHA256:
		return random.GetRandomBytes(uint32(subtle.AES128Size * 2)) // cek: 32 bytes.
	case AES192CBCHMACSHA384:
		return random.GetRandomBytes(uint32(subtle.AES192Size * 2)) // cek: 48 bytes.
	case AES256CBCHMACSHA384:
		return random.GetRandomBytes(uint32(subtle.AES256Size + subtle.AES192Size)) // cek: 56 bytes.
	case AES256CBCHMACSHA512:
		return random.GetRandomBytes(uint32(subtle.AES256Size * 2)) // cek: 64 bytes.
	default:
		return random.GetRandomBytes(uint32(32)) // default cek: 32 bytes.
	}
}
