/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle_test

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	josecipher "github.com/go-jose/go-jose/v3/cipher"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
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

func Test1PUAppendixBExample(t *testing.T) {
	aad := []byte{
		123, 34, 97, 108, 103, 34, 58, 34, 69, 67, 68, 72, 45, 49, 80, 85,
		43, 65, 49, 50, 56, 75, 87, 34, 44, 34, 101, 110, 99, 34, 58, 34,
		65, 50, 53, 54, 67, 66, 67, 45, 72, 83, 53, 49, 50, 34, 44, 34, 97,
		112, 117, 34, 58, 34, 81, 87, 120, 112, 89, 50, 85, 34, 44, 34, 97,
		112, 118, 34, 58, 34, 81, 109, 57, 105, 73, 71, 70, 117, 90, 67, 66,
		68, 97, 71, 70, 121, 98, 71, 108, 108, 34, 44, 34, 101, 112, 107,
		34, 58, 123, 34, 107, 116, 121, 34, 58, 34, 79, 75, 80, 34, 44, 34,
		99, 114, 118, 34, 58, 34, 88, 50, 53, 53, 49, 57, 34, 44, 34, 120,
		34, 58, 34, 107, 57, 111, 102, 95, 99, 112, 65, 97, 106, 121, 48,
		112, 111, 87, 53, 103, 97, 105, 120, 88, 71, 115, 57, 110, 72, 107,
		119, 103, 49, 65, 70, 113, 85, 65, 70, 97, 51, 57, 100, 121, 66, 99,
		34, 125, 125,
	}

	cek := []byte{
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
		0xdf, 0xde, 0xdd, 0xdc, 0xdb, 0xda, 0xd9, 0xd8, 0xd7, 0xd6, 0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0,
		0xcf, 0xce, 0xcd, 0xcc, 0xcb, 0xca, 0xc9, 0xc8, 0xc7, 0xc6, 0xc5, 0xc4, 0xc3, 0xc2, 0xc1, 0xc0,
	}

	iv := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	aadB64fromAAD := base64.RawURLEncoding.EncodeToString(aad)
	aadB64 := "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJ" +
		"R0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczlu" +
		"SGt3ZzFBRnFVQUZhMzlkeUJjIn19"
	require.Equal(t, aadB64, aadB64fromAAD)

	ivB64 := "AAECAwQFBgcICQoLDA0ODw"
	ctB64 := "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw"
	tagB64 := "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"

	plaintext := []byte("Three is a magic number.")

	cbcHMAC, err := josecipher.NewCBCHMAC(cek, aes.NewCipher)
	require.NoError(t, err)

	cbc := mockNONCEInCBCHMAC{
		nonce:   iv,
		cbcHMAC: cbcHMAC,
	}

	enc, err := cbc.Encrypt(plaintext, []byte(aadB64))
	require.NoError(t, err)
	require.EqualValues(t, iv, enc[:16])
	require.Equal(t, ivB64, base64.RawURLEncoding.EncodeToString(enc[:16]))
	require.Equal(t, ctB64, base64.RawURLEncoding.EncodeToString(enc[16:len(enc)-32]))
	require.Equal(t, tagB64, base64.RawURLEncoding.EncodeToString(enc[len(enc)-32:]))

	t.Logf("enc: %v", enc)
	t.Logf("iv: %v", enc[:16])
	t.Logf("iv b64: %v", base64.RawURLEncoding.EncodeToString(enc[:16]))
	t.Logf("ct: %v", enc[16:len(enc)-32])
	t.Logf("ct b64: %v", base64.RawURLEncoding.EncodeToString(enc[16:len(enc)-32]))
	t.Logf("tag: %v", enc[len(enc)-32:])
	t.Logf("tag b64: %v", base64.RawURLEncoding.EncodeToString(enc[len(enc)-32:]))
	t.Logf("aad: %v", aad)
	t.Logf("aad b64: %v", []byte(aadB64))
	t.Logf("aad b64 as string: %v", aadB64)

	dec, err := cbc.Decrypt(enc, []byte(aadB64))
	require.NoError(t, err)
	require.EqualValues(t, plaintext, dec)
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
