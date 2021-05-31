/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"strings"
	"testing"
	"time"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/aead/subtle"
)

func TestECDHESKeyTemplateSuccess(t *testing.T) {
	flagTests := []struct {
		tcName   string
		tmplFunc func() *tinkpb.KeyTemplate
		forCBC   bool
	}{
		{
			tcName:   "create ECDH NIST P-256 KW with AES256-GCM key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AES256-GCM key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AES256-GCM key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
		},
		{
			tcName:   "creat ECDH X25519 KW with XChacha20Poly1305 key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
		},
		{
			tcName:   "create ECDH NIST P-256 KW with AESCBC+HMAC key templates test",
			tmplFunc: NISTP256ECDHKWKeyTemplate,
			forCBC:   true,
		},
		{
			tcName:   "create ECDH NIST P-384 KW AESCBC+HMAC key templates test",
			tmplFunc: NISTP384ECDHKWKeyTemplate,
			forCBC:   true,
		},
		{
			tcName:   "create ECDH NIST P-521 KW AESCBC+HMAC key templates test",
			tmplFunc: NISTP521ECDHKWKeyTemplate,
			forCBC:   true,
		},
		{
			tcName:   "creat ECDH X25519 KW with AESCBC+HMAC key templates test",
			tmplFunc: X25519ECDHKWKeyTemplate,
			forCBC:   true,
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			cek := random.GetRandomBytes(uint32(32)) // default cek is 32 bytes.

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
			if strings.Contains(tc.tcName, "XChacha") { //nolint:nestif
				if tc.forCBC {
					cek = createCBCHMACCEK(tc.tcName)
					kt = X25519ECDHAESCBCHMACKeyTemplateWithCEK(cek)
				} else {
					kt = X25519ECDHXChachaKeyTemplateWithCEK(cek)
				}
			} else {
				if tc.forCBC {
					cek = createCBCHMACCEK(tc.tcName)
					kt = NISTPECDHAESCBCHMACKeyTemplateWithCEK(cek)
				} else {
					kt = NISTPECDHAES256GCMKeyTemplateWithCEK(cek)
				}
			}

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

func createCBCHMACCEK(tcName string) []byte {
	if strings.Contains(tcName, "P-384") {
		return random.GetRandomBytes(uint32(subtle.AES192Size * 2)) // cek: 48 bytes.
	} else if strings.Contains(tcName, "P-521") {
		return random.GetRandomBytes(uint32(subtle.AES256Size * 2)) // cek: 64 bytes.
	}

	return random.GetRandomBytes(uint32(subtle.AES128Size * 2))
}
