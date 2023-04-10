/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/aes"
	"errors"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v3/cipher"
	"github.com/google/tink/go/subtle/random"
)

// AESCBCHMAC is an implementation of AEAD interface.
type AESCBCHMAC struct {
	Key []byte
}

// NewAESCBCHMAC returns an AES CBC HMAC instance.
// The key argument should be the AES key, either 16, 24 or 32 bytes to select AES-128, AES-192 or AES-256.
// ivSize specifies the size of the IV in bytes.
func NewAESCBCHMAC(key []byte) (*AESCBCHMAC, error) {
	keySize := uint32(len(key))

	if err := ValidateAESKeySizeForGoJose(keySize); err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac: %w", err)
	}

	return &AESCBCHMAC{Key: key}, nil
}

// Encrypt encrypts plaintext using AES in CTR mode.
// The resulting ciphertext consists of two parts:
// (1) a random IV used for encryption and (2) the actual ciphertext.
func (a *AESCBCHMAC) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if len(plaintext) > maxInt-AESCBCIVSize {
		return nil, errors.New("aes_cbc_hmac: plaintext too long")
	}

	iv := a.newIV()

	cbcHMAC, err := josecipher.NewCBCHMAC(a.Key, aes.NewCipher)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac: %w", err)
	}

	ciphertext := cbcHMAC.Seal(nil, iv, plaintext, additionalData)

	ciphertextAndIV := make([]byte, AESCBCIVSize+len(ciphertext))
	if n := copy(ciphertextAndIV, iv); n != AESCBCIVSize {
		return nil, fmt.Errorf("aes_cbc_hmac: failed to copy IV (copied %d/%d bytes)", n, AESCBCIVSize)
	}

	copy(ciphertextAndIV[AESCBCIVSize:], ciphertext)

	return ciphertextAndIV, nil
}

// Decrypt decrypts ciphertext.
func (a *AESCBCHMAC) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	cbcAEAD, err := josecipher.NewCBCHMAC(a.Key, aes.NewCipher)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac: %w", err)
	}

	ivSize := cbcAEAD.NonceSize()
	if len(ciphertext) < ivSize {
		return nil, errors.New("aes_cbc_hmac: ciphertext too short")
	}

	iv := ciphertext[:ivSize]

	plaintext, err := cbcAEAD.Open(nil, iv, ciphertext[ivSize:], additionalData)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac: failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// newIV creates a new IV for encryption.
func (a *AESCBCHMAC) newIV() []byte {
	return random.GetRandomBytes(uint32(AESCBCIVSize))
}
