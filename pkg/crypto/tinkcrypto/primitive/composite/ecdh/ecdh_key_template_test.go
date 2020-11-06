/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
)

func TestECDHESKeyTemplateSuccess(t *testing.T) {
	flagTests := []struct {
		tcName    string
		curveType string
		tmplFunc  func() *tinkpb.KeyTemplate
	}{
		{
			tcName:    "create ECDH AES-GCM 256 key templates test",
			curveType: "P-256",
			tmplFunc:  ECDH256KWAES256GCMKeyTemplate,
		},
		{
			tcName:    "create ECDH AES-GCM 384 key templates test",
			curveType: "P-384",
			tmplFunc:  ECDH384KWAES256GCMKeyTemplate,
		},
		{
			tcName:    "create ECDH AES-GCM 521 key templates test",
			curveType: "P-521",
			tmplFunc:  ECDH521KWAES256GCMKeyTemplate,
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
			kt = AES256GCMKeyTemplateWithCEK(cek)

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
