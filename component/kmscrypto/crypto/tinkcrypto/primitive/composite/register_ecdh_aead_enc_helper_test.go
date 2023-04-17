/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	subtleaead "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/mac"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	cbchmacaead "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	subtlecbchmacaead "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	aeadpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
)

func newKeyTemplates() ([]*tinkpb.KeyTemplate, []int) {
	twoKeys := 2

	return []*tinkpb.KeyTemplate{
			aead.ChaCha20Poly1305KeyTemplate(),
			aead.XChaCha20Poly1305KeyTemplate(),
			aead.AES256GCMKeyTemplate(),
			aead.AES128GCMKeyTemplate(),
			cbchmacaead.AES128CBCHMACSHA256KeyTemplate(),
			cbchmacaead.AES192CBCHMACSHA384KeyTemplate(),
			cbchmacaead.AES256CBCHMACSHA384KeyTemplate(),
			cbchmacaead.AES256CBCHMACSHA512KeyTemplate(),
		},
		[]int{
			chacha20poly1305.KeySize,
			chacha20poly1305.KeySize,
			subtlecbchmacaead.AES256Size,
			subtlecbchmacaead.AES128Size,
			subtlecbchmacaead.AES128Size * twoKeys,
			subtlecbchmacaead.AES192Size * twoKeys,
			subtlecbchmacaead.AES256Size + subtlecbchmacaead.AES192Size,
			subtlecbchmacaead.AES256Size * twoKeys,
		}
}

func TestCipherGetters(t *testing.T) {
	keyTemplates, _ := newKeyTemplates()

	for _, c := range keyTemplates {
		rDem, err := NewRegisterCompositeAEADEncHelper(c)
		require.NoError(t, err, "error generating a content encryption helper")

		switch rDem.encKeyURL {
		case AESCBCHMACAEADTypeURL:
			require.EqualValues(t, subtlecbchmacaead.AESCBCIVSize, rDem.GetIVSize())

			format := new(aeadpb.AesCbcHmacAeadKeyFormat)
			err = proto.Unmarshal(c.Value, format)
			require.NoError(t, err)

			require.EqualValues(t, format.HmacKeyFormat.Params.TagSize, rDem.GetTagSize())
		case AESGCMTypeURL:
			require.EqualValues(t, subtleaead.AESGCMIVSize, rDem.GetIVSize())
			require.EqualValues(t, subtleaead.AESGCMTagSize, rDem.GetTagSize())
		case ChaCha20Poly1305TypeURL:
			require.EqualValues(t, chacha20poly1305.NonceSize, rDem.GetIVSize())
			require.EqualValues(t, poly1305.TagSize, rDem.GetTagSize())
		case XChaCha20Poly1305TypeURL:
			require.EqualValues(t, chacha20poly1305.NonceSizeX, rDem.GetIVSize())
			require.EqualValues(t, poly1305.TagSize, rDem.GetTagSize())
		}
	}
}

func TestCipherGettersFailures(t *testing.T) {
	tests := []struct {
		name       string
		typeURL    string
		formatName string
	}{
		{
			name:       "AESCBCHMAC AEAD error",
			typeURL:    AESCBCHMACAEADTypeURL,
			formatName: "cbcHMACKeyFormat",
		},
		{
			name:       "AESGCM AEAD error",
			typeURL:    AESGCMTypeURL,
			formatName: "gcmKeyFormat",
		},
		{
			name:       "C20P AEAD error",
			typeURL:    ChaCha20Poly1305TypeURL,
			formatName: "chachaKeyFormat",
		},
		{
			name:       "XC20P AEAD error",
			typeURL:    XChaCha20Poly1305TypeURL,
			formatName: "xChachaKeyFormat",
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			c := &tinkpb.KeyTemplate{
				TypeUrl:          tc.typeURL,
				Value:            []byte("bad serialized key"),
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			}

			rDem, err := NewRegisterCompositeAEADEncHelper(c)
			require.Error(t, err)
			require.Contains(t, err.Error(), fmt.Sprintf("compositeAEADEncHelper: failed to unmarshal %s", tc.formatName))
			require.Empty(t, rDem)
		})
	}
}

func TestUnsupportedKeyTemplates(t *testing.T) {
	uTemplates := []*tinkpb.KeyTemplate{
		signature.ECDSAP256KeyTemplate(),
		mac.HMACSHA256Tag256KeyTemplate(),
		{TypeUrl: "some url", Value: []byte{0}},
		{TypeUrl: AESGCMTypeURL},
		{TypeUrl: AESGCMTypeURL, Value: []byte("123")},
	}

	for _, l := range uTemplates {
		_, err := NewRegisterCompositeAEADEncHelper(l)
		require.Errorf(t, err, "unsupported key template %s should have generated error: %v", l)
	}
}

func TestAead(t *testing.T) {
	keyTemplates, keysSizes := newKeyTemplates()

	for i, c := range keyTemplates {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
		rEnc, err := NewRegisterCompositeAEADEncHelper(c)
		require.NoError(t, err, "error generating a content encryption helper")

		keySize := uint32(keysSizes[i])
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

func TestBuildEncDecData(t *testing.T) {
	rEnc, err := NewRegisterCompositeAEADEncHelper(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	refEncData := &EncryptedData{
		IV:         random.GetRandomBytes(uint32(rEnc.GetIVSize())),
		Ciphertext: []byte("ciphertext"),
		Tag:        random.GetRandomBytes(uint32(rEnc.GetTagSize())),
	}

	preBuiltCT := append(refEncData.IV, refEncData.Ciphertext...)
	preBuiltCT = append(preBuiltCT, refEncData.Tag...)

	// test BuildDecData
	finalCT := rEnc.BuildDecData(refEncData)
	require.EqualValues(t, preBuiltCT, finalCT)

	// test BuildEncData
	mEncData, err := rEnc.BuildEncData(preBuiltCT)
	require.NoError(t, err)

	mRefEncData, err := json.Marshal(refEncData)
	require.NoError(t, err)
	require.EqualValues(t, mRefEncData, mEncData)
}
