/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle_test

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/aead/subtle"
)

func TestNewAESCBC(t *testing.T) {
	key := make([]byte, 64)

	// Test various key sizes with a fixed IV size.
	for i := 0; i < 64; i++ {
		k := key[:i]
		c, err := subtle.NewAESCBC(k)

		switch len(k) {
		case 16, 24, 32:
			// Valid key sizes.
			require.NoError(t, err, "want: valid cipher (key size=%d), got: error %v", len(k), err)

			// Verify that the struct contents are correctly set.
			require.Equal(t, len(k), len(c.Key), "want: key size=%d, got: key size=%d", len(k), len(c.Key))
		default:
			// Invalid key sizes.
			require.EqualError(t, err, fmt.Sprintf("aes_cbc: NewAESCBC() invalid AES key size; want 16, 24 or 32,"+
				" got %d", i))
		}
	}
}

func TestNistTestVector(t *testing.T) {
	// NIST SP 800-38A pp 27
	key, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	require.NoError(t, err)

	// NIST IV
	iv := "000102030405060708090a0b0c0d0e0f"
	// NIST ciphertext blocks
	c := "7649abac8119b246cee98e9b12e9197d" +
		"5086cb9b507219ee95db113a917678b2" +
		"73bed6b8e3c1743b7116e69e22229516" +
		"3ff1caa1681fac09120eca307586e1a7"
	ciphertext, err := hex.DecodeString(iv + c)
	require.NoError(t, err)

	// NIST plaintext blocks
	p := "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
	message, err := hex.DecodeString(p)
	require.NoError(t, err)

	cbc, err := subtle.NewAESCBC(key)
	require.NoError(t, err)

	plaintext, err := cbc.Decrypt(ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, plaintext, message, "plaintext doesn't match message")

	ciphertext1, err := cbc.Encrypt(message)
	require.NoError(t, err)

	plaintext2, err := cbc.Decrypt(ciphertext1)
	require.NoError(t, err)
	require.EqualValues(t, plaintext2, message, "encrypted plaintext doesn't match message")
}

func TestMultipleEncrypt(t *testing.T) {
	key := random.GetRandomBytes(16)

	cbc, err := subtle.NewAESCBC(key)
	require.NoError(t, err)

	plaintext := []byte("Some data to encrypt.")
	ciphertext1, err := cbc.Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext2, err := cbc.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotEqualValues(t, ciphertext1, ciphertext2, "the two ciphertexts cannot be equal")

	// Encrypt 100 times and verify that the result is 100 different ciphertexts.
	ciphertexts := map[string]bool{}

	for i := 0; i < 100; i++ {
		c, err := cbc.Encrypt(plaintext)
		require.NoErrorf(t, err, fmt.Sprintf("encryption failed for iteration %d, error: %v", i, err))

		ciphertexts[string(c)] = true
	}

	require.Equal(t, 100, len(ciphertexts))
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)

	cbc, err := subtle.NewAESCBC(key)
	require.NoError(t, err)

	message := []byte("Some data to encrypt.")
	ciphertext, err := cbc.Encrypt(message)
	require.NoError(t, err)

	validateCiphertext(t, message, ciphertext, -1)

	plaintext, err := cbc.Decrypt(ciphertext)
	require.NoError(t, err)
	require.EqualValues(t, message, plaintext)

	t.Run("failure - decrypt short ciphertext", func(t *testing.T) {
		_, err = cbc.Decrypt([]byte("short ct"))
		require.EqualError(t, err, "aes_cbc: ciphertext too short")
	})

	t.Run("failure - decrypt ciphertext not bloc multiple", func(t *testing.T) {
		_, err = cbc.Decrypt([]byte("short ciphertext not multiple"))
		require.EqualError(t, err, "aes_cbc: invalid ciphertext padding")
	})
}

func TestFailEncryptDecrypt(t *testing.T) {
	t.Run("failure - encrypt failing with invalid key size", func(t *testing.T) {
		key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
		require.NoError(t, err)

		cbc, err := subtle.NewAESCBC(key)
		require.NoError(t, err)

		// set invalid key size
		cbc.Key = []byte("bad key Size")

		_, err = cbc.Encrypt([]byte("plaintext"))
		require.EqualError(t, err, "aes_cbc: Encrypt() aes_cbc: failed to create block cipher, error: crypto/aes: "+
			"invalid key size 12")

		_, err = cbc.Decrypt([]byte("ciphertext bloc size"))
		require.EqualError(t, err, "aes_cbc: Decrypt() aes_cbc: failed to create block cipher, error: crypto/aes:"+
			" invalid key size 12")
	})
}

func TestEncryptRandomMessage(t *testing.T) {
	key := random.GetRandomBytes(16)

	cbc, err := subtle.NewAESCBC(key)
	require.NoError(t, err)

	for i := 0; i < 256; i++ {
		message := random.GetRandomBytes(uint32(i))
		ciphertext, err := cbc.Encrypt(message)
		require.NoError(t, err)

		validateCiphertext(t, message, ciphertext, i)

		plaintext, err := cbc.Decrypt(ciphertext)
		require.NoError(t, err, fmt.Sprintf("decryption failed at iteration %d, error: %v", i, err))
		require.EqualValuesf(t, message, plaintext, fmt.Sprintf("plaintext doesn't match message, i = %d", i))
	}
}

func TestEncryptRandomKeyAndMessage(t *testing.T) {
	for i := 0; i < 256; i++ {
		key := random.GetRandomBytes(16)

		cbc, err := subtle.NewAESCBC(key)
		require.NoError(t, err)

		message := random.GetRandomBytes(uint32(i))

		ciphertext, err := cbc.Encrypt(message)
		require.NoErrorf(t, err, "encryption failed at iteration %d", i)

		validateCiphertext(t, message, ciphertext, i)

		plaintext, err := cbc.Decrypt(ciphertext)
		require.NoError(t, err, fmt.Sprintf("decryption failed at iteration %d, error: %v", i, err))
		require.EqualValuesf(t, message, plaintext, fmt.Sprintf("plaintext doesn't match message, i = %d", i))
	}
}

func validateCiphertext(t *testing.T, plaintext, ciphertext []byte, id int) {
	t.Helper()

	padding := aes.BlockSize - ((len(plaintext) + subtle.AESCBCIVSize) % aes.BlockSize)
	expectedCTSize := len(plaintext) + subtle.AESCBCIVSize + padding
	require.Equalf(t, len(ciphertext), expectedCTSize, fmt.Sprintf("invalid ciphertext length for i = %d, "+
		"ciphertext length: %d, msg length: %d", id, len(ciphertext), len(plaintext)+subtle.AESCBCIVSize))
}

func TestPadUnpad(t *testing.T) {
	// test pad empty text.
	ciphertext := []byte("")
	paddedCT := subtle.Pad(ciphertext, 0, aes.BlockSize)
	unpaddedCT := subtle.Unpad(paddedCT)
	require.EqualValues(t, ciphertext, unpaddedCT)

	newCiphertext := append(ciphertext, byte(0))
	for i := 1; i < 3*aes.BlockSize+1; i++ {
		paddedCT = subtle.Pad(newCiphertext, len(newCiphertext), aes.BlockSize)
		unpaddedCT = subtle.Unpad(paddedCT)
		require.EqualValues(t, newCiphertext, unpaddedCT)

		newCiphertext = append(newCiphertext, byte(i))
	}
}
