/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcomm

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

// MockAuthCrypt mock auth crypt.
type MockAuthCrypt struct {
	EncryptValue func(cty string, payload, senderPubKey []byte, recipients [][]byte) ([]byte, error)
	DecryptValue func(envelope []byte) (*transport.Envelope, error)
	Type         string
}

// Pack mock message packing.
func (m *MockAuthCrypt) Pack(cty string, payload, senderPubKey []byte, recipients [][]byte) ([]byte, error) {
	return m.EncryptValue(cty, payload, senderPubKey, recipients)
}

// Unpack mock message unpacking.
func (m *MockAuthCrypt) Unpack(envelope []byte) (*transport.Envelope, error) {
	return m.DecryptValue(envelope)
}

// EncodingType mock encoding type.
func (m *MockAuthCrypt) EncodingType() string {
	return m.Type
}
