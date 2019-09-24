/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
)

// MockAuthCrypt mock auth crypt
type MockAuthCrypt struct {
	EncryptValue func(payload []byte, sender crypto.KeyPair, recipients [][]byte) ([]byte, error)
	DecryptValue func(envelope []byte, recipientKeyPair crypto.KeyPair) ([]byte, error)
}

// Encrypt mock encrypt
func (m *MockAuthCrypt) Encrypt(payload []byte, sender crypto.KeyPair,
	recipients [][]byte) ([]byte, error) {
	return m.EncryptValue(payload, sender, recipients)
}

// Decrypt mock decrypt
func (m *MockAuthCrypt) Decrypt(envelope []byte, recipientKeyPair crypto.KeyPair) ([]byte, error) {
	return m.DecryptValue(envelope, recipientKeyPair)
}
