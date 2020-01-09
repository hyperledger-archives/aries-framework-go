/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

// Crypto mock
type Crypto struct {
	EncryptValue      []byte
	EncryptNonceValue []byte
	EncryptErr        error
	DecryptValue      []byte
	DecryptErr        error
	SignValue         []byte
	SignErr           error
	VerifyErr         error
}

// Encrypt mocked value
func (c *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	return c.EncryptValue, c.EncryptNonceValue, c.EncryptErr
}

// Decrypt mocked value
func (c *Crypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	return c.DecryptValue, c.DecryptErr
}

// Sign mocked value
func (c *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	return c.SignValue, c.SignErr
}

// Verify mocked value
func (c *Crypto) Verify(signature, msg []byte, kh interface{}) error {
	return c.VerifyErr
}
