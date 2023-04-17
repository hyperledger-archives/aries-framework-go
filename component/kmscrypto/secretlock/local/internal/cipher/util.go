/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

// package cipher provides utility functions to support the secretlock.

// CreateAESCipher will create a new AES cipher for the given key.
// This function is to be used by secretlock/local package only.
func CreateAESCipher(masterKey []byte) (cipher.AEAD, error) {
	cipherBlock, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(cipherBlock)
}
