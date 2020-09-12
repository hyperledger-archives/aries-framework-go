/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

var keyTemplates = map[*tinkpb.KeyTemplate]int{
	aead.ChaCha20Poly1305KeyTemplate():  32,
	aead.XChaCha20Poly1305KeyTemplate(): 32,
	aead.AES256GCMKeyTemplate():         32,
	aead.AES128GCMKeyTemplate():         16,
}

func TestCipherGetters(t *testing.T) {
	for c, l := range keyTemplates {
		rDem, err := NewRegisterCompositeAEADEncHelper(c)
		require.NoError(t, err, "error generating a content encryption helper")

		require.EqualValues(t, l, rDem.GetSymmetricKeySize(), "incorrect template key size")

		switch rDem.encKeyURL {
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
	for c := range keyTemplates {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
		rEnc, err := NewRegisterCompositeAEADEncHelper(c)
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

func TestBuildEncDecData(t *testing.T) {
	rEnc, err := NewRegisterCompositeAEADEncHelper(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	refEncData := &EncryptedData{
		EncAlg:     "A256GCM",
		IV:         random.GetRandomBytes(uint32(rEnc.GetIVSize())),
		Ciphertext: []byte("ciphertext"),
		Tag:        random.GetRandomBytes(uint32(rEnc.GetTagSize())),
		Recipients: []*RecipientWrappedKey{
			{
				KID:          "kid",
				EncryptedCEK: []byte("cek"),
				EPK:          PublicKey{},
				Alg:          "P-256",
			},
		},
		SingleRecipientAAD: []byte("{\"enc\":\"testAlg\"}"),
	}

	preBuiltCT := append(refEncData.IV, refEncData.Ciphertext...)
	preBuiltCT = append(preBuiltCT, refEncData.Tag...)

	// test BuildDecData
	finalCT := rEnc.BuildDecData(refEncData)
	require.EqualValues(t, preBuiltCT, finalCT)

	// test BuildEncData
	mEncData, err := rEnc.BuildEncData(refEncData.EncAlg, refEncData.EncType, refEncData.Recipients, preBuiltCT,
		refEncData.SingleRecipientAAD)
	require.NoError(t, err)

	mRefEncData, err := json.Marshal(refEncData)
	require.NoError(t, err)
	require.EqualValues(t, mRefEncData, mEncData)
}

func TestMergeSingleRecipientsHeadersFailureWithUnsetCurve(t *testing.T) {
	aad := map[string]string{"enc": "test"}

	mAAD, e := json.Marshal(aad)
	require.NoError(t, e)

	for c := range keyTemplates {
		cEnc, err := NewRegisterCompositeAEADEncHelper(c)
		require.NoError(t, err)

		wk := &RecipientWrappedKey{
			EPK: PublicKey{},
		}

		// fail with aad not base64URL encoded
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte("aad not base64URL encoded"))
		require.EqualError(t, err, "illegal base64 data at input byte 3")

		badAAD := base64.RawURLEncoding.EncodeToString([]byte("aad not a json format"))

		// fail with aad not being a marshalled json
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte(badAAD))
		require.EqualError(t, err, "invalid character 'a' looking for beginning of value")

		// fail with epk curve not set
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)))
		require.EqualError(t, err, "unsupported curve")

		// set epk curve for subsequent tests
		wk.EPK.Curve = elliptic.P256().Params().Name

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		cEnc.marshalFunc = fm.failingMarshal

		// fail KID marshalling
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)))
		require.EqualError(t, err, errFailingMarshal.Error())

		fm = &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 1,
		}

		cEnc.marshalFunc = fm.failingMarshal

		// fail Alg marshalling
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)))
		require.EqualError(t, err, errFailingMarshal.Error())

		fm = &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 2,
		}

		cEnc.marshalFunc = fm.failingMarshal
		// fail EPK marshalling
		_, err = cEnc.MergeSingleRecipientHeaders(wk, []byte(base64.RawURLEncoding.EncodeToString(mAAD)))
		require.EqualError(t, err, errFailingMarshal.Error())
	}
}

var errFailingMarshal = fmt.Errorf("json marshal error")

type failingMarshaller struct {
	numTimesMarshalCalled                int
	numTimesMarshalCalledBeforeReturnErr int
}

func (m *failingMarshaller) failingMarshal(_ interface{}) ([]byte, error) {
	if m.numTimesMarshalCalled == m.numTimesMarshalCalledBeforeReturnErr {
		return nil, errFailingMarshal
	}

	m.numTimesMarshalCalled++

	return nil, nil
}
