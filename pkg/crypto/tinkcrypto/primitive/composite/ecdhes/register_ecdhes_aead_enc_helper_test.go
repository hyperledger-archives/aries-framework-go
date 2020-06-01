/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"encoding/hex"
	"testing"

	"github.com/google/tink/go/aead"
	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/mac"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

var (
	// nolint:gochecknoglobals
	keyTemplates = map[*tinkpb.KeyTemplate]int{
		aead.ChaCha20Poly1305KeyTemplate():  32,
		aead.XChaCha20Poly1305KeyTemplate(): 32,
		aead.AES256GCMKeyTemplate():         32,
		aead.AES128GCMKeyTemplate():         16,
	}
)

func TestCipherGetters(t *testing.T) {
	for c, l := range keyTemplates {
		rDem, err := newRegisterECDHESAEADEncHelper(c)
		require.NoError(t, err, "error generating a content encryption helper")

		require.EqualValues(t, l, rDem.GetSymmetricKeySize(), "incorrect template key size")

		switch rDem.encKeyURL {
		case aesGCMTypeURL:
			require.EqualValues(t, subtleaead.AESGCMIVSize, rDem.GetIVSize())
			require.EqualValues(t, subtleaead.AESGCMTagSize, rDem.GetTagSize())
		case chaCha20Poly1305TypeURL:
			require.EqualValues(t, chacha20poly1305.NonceSize, rDem.GetIVSize())
			require.EqualValues(t, poly1305.TagSize, rDem.GetTagSize())
		case xChaCha20Poly1305TypeURL:
			require.EqualValues(t, chacha20poly1305.NonceSizeX, rDem.GetIVSize())
			require.EqualValues(t, poly1305.TagSize, rDem.GetTagSize())
		}
	}
}

func TestUnsupportedKeyTemplates(t *testing.T) {
	var uTemplates = []*tinkpb.KeyTemplate{
		signature.ECDSAP256KeyTemplate(),
		mac.HMACSHA256Tag256KeyTemplate(),
		{TypeUrl: "some url", Value: []byte{0}},
		{TypeUrl: aesGCMTypeURL},
		{TypeUrl: aesGCMTypeURL, Value: []byte("123")},
	}

	for _, l := range uTemplates {
		_, err := newRegisterECDHESAEADEncHelper(l)
		require.Errorf(t, err, "unsupported key template %s should have generated error: %v", l)
	}
}

func TestAead(t *testing.T) {
	for c := range keyTemplates {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
		rEnc, err := newRegisterECDHESAEADEncHelper(c)
		require.NoError(t, err, "error generating a content encryption helper")

		keySize := uint32(rEnc.GetSymmetricKeySize())
		sk := random.GetRandomBytes(keySize)
		a, err := rEnc.GetAEAD(sk)
		require.NoError(t, err, "error getting AEAD primitive")

		ct, err := a.Encrypt(pt, ad)
		require.NoError(t, err, "error encrypting")

		dt, err := a.Decrypt(ct, ad)
		require.NoError(t, err, "error decrypting")

		require.EqualValuesf(t, pt, dt, "decryption not inverse of encryption,\n want :%s,\n got: %s",
			hex.Dump(pt), hex.Dump(dt))

		// shorter symmetric key
		sk = random.GetRandomBytes(keySize - 1)
		_, err = rEnc.GetAEAD(sk)
		require.Error(t, err, "retrieving AEAD primitive should have failed")

		// longer symmetric key
		sk = random.GetRandomBytes(keySize + 1)
		_, err = rEnc.GetAEAD(sk)
		require.Error(t, err, "retrieving AEAD primitive should have failed")

		// set bad keyData
		tmpKeyData := rEnc.keyData
		rEnc.keyData = []byte{0, 1, 3}
		sk = random.GetRandomBytes(keySize)
		_, err = rEnc.GetAEAD(sk)
		require.Error(t, err, "retrieving AEAD primitive should have failed")

		// set bad key URL
		rEnc.keyData = tmpKeyData
		rEnc.encKeyURL = "bad.url"
		_, err = rEnc.GetAEAD(sk)
		require.Error(t, err, "retrieving AEAD primitive should have failed")
	}
}
