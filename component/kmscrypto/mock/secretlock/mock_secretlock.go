/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secretlock

import (
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
)

// MockSecretLock mocking a Secret Lock service.
type MockSecretLock struct {
	ValEncrypt string
	ValDecrypt string
	ErrEncrypt error
	ErrDecrypt error
}

// Encrypt req for master key in keyURI.
func (m *MockSecretLock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	if m.ErrEncrypt != nil {
		return nil, m.ErrEncrypt
	}

	return &secretlock.EncryptResponse{Ciphertext: m.ValEncrypt}, nil
}

// Decrypt req for master key in keyURI.
func (m *MockSecretLock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	if m.ErrDecrypt != nil {
		return nil, m.ErrDecrypt
	}

	return &secretlock.DecryptResponse{Plaintext: m.ValDecrypt}, nil
}
