/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/cipher"
	"errors"

	chacha "golang.org/x/crypto/chacha20poly1305"
)

// TODO https://github.com/hyperledger/aries-framework-go/issues/475 pull cipher into separate crypter

// createCipher will create and return a new Chacha20Poly1305 cipher for the given nonceSize and symmetric key.
func createCipher(nonceSize int, symKey []byte) (cipher.AEAD, error) {
	switch nonceSize {
	case chacha.NonceSize:
		return chacha.New(symKey)
	case chacha.NonceSizeX:
		return chacha.NewX(symKey)
	default:
		return nil, errors.New("cipher cannot be created with bad nonce size and shared symmetric Key combo")
	}
}
