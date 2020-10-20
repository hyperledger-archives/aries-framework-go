/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
)

type mockKeyWrapperSupport struct {
	getCurveVal     elliptic.Curve
	getCurveErr     error
	generateKeyVal  *ecdsa.PrivateKey
	generateKeyErr  error
	createCipherVal cipher.Block
	createCipherErr error
	wrapVal         []byte
	wrapErr         error
	unwrapVal       []byte
	unwrapErr       error
}

func (w *mockKeyWrapperSupport) getCurve(curve string) (elliptic.Curve, error) {
	return w.getCurveVal, w.getCurveErr
}

func (w *mockKeyWrapperSupport) generateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return w.generateKeyVal, w.generateKeyErr
}

func (w *mockKeyWrapperSupport) createCipher(kek []byte) (cipher.Block, error) {
	return w.createCipherVal, w.createCipherErr
}

func (w *mockKeyWrapperSupport) wrap(block cipher.Block, cek []byte) ([]byte, error) {
	return w.wrapVal, w.wrapErr
}

func (w *mockKeyWrapperSupport) unwrap(block cipher.Block, wrappedKey []byte) ([]byte, error) {
	return w.unwrapVal, w.unwrapErr
}

func TestWrapKey_Failure(t *testing.T) {
	recipientKey, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(keySize))
	apu := []byte("sender")
	apv := []byte("recipient")

	// test WrapKey with mocked getCurve error
	c := Crypto{kw: &mockKeyWrapperSupport{getCurveErr: errors.New("bad Curve")}}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: failed to get curve of recipient key: bad Curve")

	// test WrapKey with mocked generateKey error
	c = Crypto{kw: &mockKeyWrapperSupport{generateKeyErr: errors.New("genKey failed")}}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: failed to generate EPK: genKey failed")

	epk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// test WrapKey with mocked createCipher error
	c = Crypto{
		kw: &mockKeyWrapperSupport{
			createCipherErr: errors.New("createCipher failed"),
			generateKeyVal:  epk,
		},
	}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: failed to create new Cipher: createCipher failed")

	aesCipher, err := aes.NewCipher(random.GetRandomBytes(uint32(keySize)))
	require.NoError(t, err)

	// test WrapKey with mocked Wrap call error
	c = Crypto{
		kw: &mockKeyWrapperSupport{
			createCipherVal: aesCipher,
			generateKeyVal:  epk,
			wrapErr:         errors.New("wrap error"),
		},
	}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: failed to wrap key: wrap error")
}

func TestUnwrapKey_Failure(t *testing.T) {
	recipientKey, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(keySize))
	apu := []byte("sender")
	apv := []byte("recipient")

	validCrypter, err := New()
	require.NoError(t, err)

	wpKey, err := validCrypter.WrapKey(cek, apu, apv, recipientKey)
	require.NoError(t, err)

	// test UnwrapKey with mocked getCurve error
	c := Crypto{kw: &mockKeyWrapperSupport{getCurveErr: errors.New("bad Curve")}}

	_, err = c.UnwrapKey(wpKey, recipientKey)
	require.EqualError(t, err, "unwrapKey: failed to GetCurve: bad Curve")

	// test UnwrapKey with mocked createCipher error
	c = Crypto{
		kw: &mockKeyWrapperSupport{
			createCipherErr: errors.New("createCipher failed"),
			getCurveVal:     elliptic.P256(),
		},
	}

	_, err = c.UnwrapKey(wpKey, recipientKey)
	require.EqualError(t, err, "unwrapKey: failed to create new Cipher: createCipher failed")

	// test UnwrapKey with mocked unwrap error
	aesCipher, err := aes.NewCipher(random.GetRandomBytes(uint32(keySize)))
	require.NoError(t, err)

	c = Crypto{
		kw: &mockKeyWrapperSupport{
			createCipherVal: aesCipher,
			getCurveVal:     elliptic.P256(),
			unwrapErr:       errors.New("unwrap error"),
		},
	}

	_, err = c.UnwrapKey(wpKey, recipientKey)
	require.EqualError(t, err, "unwrapKey: failed to unwrap key: unwrap error")
}
