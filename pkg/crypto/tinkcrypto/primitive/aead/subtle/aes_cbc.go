/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/google/tink/go/subtle/random"
)

const (
	// AESCBCIVSize is the IV size that this implementation supports.
	AESCBCIVSize = 16
)

// AESCBC is an implementation of AEAD interface.
type AESCBC struct {
	Key []byte
}

// NewAESCBC returns an AESCBC instance.
// The key argument should be the AES key, either 16, 24 or 32 bytes to select
// AES-128, AES-192 or AES-256.
func NewAESCBC(key []byte) (*AESCBC, error) {
	keySize := uint32(len(key))
	if err := ValidateAESKeySize(keySize); err != nil {
		return nil, fmt.Errorf("aes_cbc: NewAESCBC() %w", err)
	}

	return &AESCBC{Key: key}, nil
}

// Encrypt encrypts plaintext using AES in CTR mode.
// The resulting ciphertext consists of two parts:
// (1) the IV used for encryption and (2) the actual ciphertext.
func (a *AESCBC) Encrypt(plaintext []byte) ([]byte, error) {
	plainTextSize := len(plaintext)
	if plainTextSize > maxInt-AESCBCIVSize {
		return nil, errors.New("aes_cbc: plaintext too long")
	}

	iv := a.newIV()

	cbc, err := newCipher(a.Key, iv, false)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: Encrypt() %w", err)
	}

	ciphertext := make([]byte, AESCBCIVSize+plainTextSize)
	if n := copy(ciphertext, iv); n != AESCBCIVSize {
		return nil, fmt.Errorf("aes_cbc: failed to copy IV (copied %d/%d bytes)", n, AESCBCIVSize)
	}

	if n := copy(ciphertext[AESCBCIVSize:], plaintext); n != plainTextSize {
		return nil, fmt.Errorf("aes_cbc: failed to copy plaintext (copied %d/%d bytes)", n, plainTextSize)
	}

	ciphertext = Pad(ciphertext, plainTextSize, cbc.BlockSize())

	cbc.CryptBlocks(ciphertext[AESCBCIVSize:], ciphertext[AESCBCIVSize:])

	return ciphertext, nil
}

// Decrypt decrypts ciphertext.
func (a *AESCBC) Decrypt(ciphertext []byte) ([]byte, error) {
	ciphertextSize := len(ciphertext)
	if ciphertextSize < AESCBCIVSize {
		return nil, errors.New("aes_cbc: ciphertext too short")
	}

	iv := ciphertext[:AESCBCIVSize]

	cbc, err := newCipher(a.Key, iv, true)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: Decrypt() %w", err)
	}

	blockSize := cbc.BlockSize()

	if len(ciphertext[AESCBCIVSize:])%blockSize > 0 {
		return nil, errors.New("aes_cbc: invalid ciphertext padding")
	}

	plaintext := make([]byte, ciphertextSize-AESCBCIVSize)
	cbc.CryptBlocks(plaintext, ciphertext[AESCBCIVSize:])

	if len(plaintext) == 0 {
		return plaintext, nil
	}

	// unpad plaintext if not block size.
	last := plaintext[len(plaintext)-1]
	count := int(last)

	if count == 0 || count > blockSize || count > len(plaintext) {
		return nil, errors.New("aes_cbc: invalid padding")
	}

	padding := bytes.Repeat([]byte{last}, count)
	if bytes.HasSuffix(plaintext, padding) {
		// padding was found, trim it and return remaining plaintext.
		return plaintext[:len(plaintext)-len(padding)], nil
	}

	// padding not found, return full plaintext.
	return plaintext, nil
}

// newIV creates a new IV for encryption.
func (a *AESCBC) newIV() []byte {
	return random.GetRandomBytes(uint32(AESCBCIVSize))
}

// newCipher creates a new AES-CBC cipher using the given key, IV and the crypto library.
func newCipher(key, iv []byte, decrypt bool) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: failed to create block cipher, error: %w", err)
	}

	// If the IV is less than BlockSize bytes we need to pad it with zeros otherwise NewCBCEncrypter will panic.
	if len(iv) < aes.BlockSize {
		paddedIV := make([]byte, aes.BlockSize)
		if n := copy(paddedIV, iv); n != len(iv) {
			return nil, errors.New("aes_cbc: failed to pad IV")
		}

		if !decrypt {
			return cipher.NewCBCEncrypter(block, paddedIV), nil
		}

		return cipher.NewCBCDecrypter(block, paddedIV), nil
	}

	if !decrypt {
		return cipher.NewCBCEncrypter(block, iv), nil
	}

	return cipher.NewCBCDecrypter(block, iv), nil
}

// Pad text to blockSize.
func Pad(text []byte, originalTextSize, blockSize int) []byte {
	// pad to block size if needed.
	missing := blockSize - (originalTextSize % blockSize)
	if missing > 0 && originalTextSize > 0 {
		text = append(text, bytes.Repeat([]byte{byte(missing)}, missing)...)
	}

	return text
}
