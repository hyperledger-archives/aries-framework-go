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
	ComputeMACValue   []byte
	ComputeMACErr     error
	VerifyMACErr      error
}

// Encrypt returns mocked values and a mocked error
func (c *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	return c.EncryptValue, c.EncryptNonceValue, c.EncryptErr
}

// Decrypt returns a mocked value and a mocked error
func (c *Crypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	return c.DecryptValue, c.DecryptErr
}

// Sign returns a mocked value and a mocked error
func (c *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	return c.SignValue, c.SignErr
}

// Verify returns a mocked value
func (c *Crypto) Verify(signature, msg []byte, kh interface{}) error {
	return c.VerifyErr
}

// ComputeMAC returns a mocked value and a mocked error
func (c *Crypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	return c.ComputeMACValue, c.ComputeMACErr
}

// VerifyMAC returns a mocked value
func (c *Crypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	return c.VerifyMACErr
}
