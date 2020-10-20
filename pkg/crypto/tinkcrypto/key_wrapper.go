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

	hybrid "github.com/google/tink/go/hybrid/subtle"
	josecipher "github.com/square/go-jose/v3/cipher"
)

type keyWrapper interface {
	getCurve(curve string) (elliptic.Curve, error)
	generateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error)
	createCipher(key []byte) (cipher.Block, error)
	wrap(block cipher.Block, cek []byte) ([]byte, error)
	unwrap(block cipher.Block, encryptedKey []byte) ([]byte, error)
}

type keyWrapperSupport struct{}

func (w *keyWrapperSupport) getCurve(curve string) (elliptic.Curve, error) {
	return hybrid.GetCurve(curve)
}

func (w *keyWrapperSupport) generateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (w *keyWrapperSupport) createCipher(kek []byte) (cipher.Block, error) {
	return aes.NewCipher(kek)
}

func (w *keyWrapperSupport) wrap(block cipher.Block, cek []byte) ([]byte, error) {
	return josecipher.KeyWrap(block, cek)
}

func (w *keyWrapperSupport) unwrap(block cipher.Block, encryptedKey []byte) ([]byte, error) {
	return josecipher.KeyUnwrap(block, encryptedKey)
}
