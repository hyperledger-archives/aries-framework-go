/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacykms

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// CloseableKMS mock Key Management Service (KMS)
type CloseableKMS struct {
	CreateEncryptionKeyValue string
	CreateKeyErr             error
	CreateSigningKeyValue    string
	FindVerKeyValue          int
	FindVerKeyErr            error
	SignMessageValue         []byte
	SignMessageErr           error
	DecryptMessageValue      []byte
	DecryptMessageErr        error
	PackValue                []byte
	PackErr                  error
	UnpackValue              *transport.Envelope
	UnpackErr                error
	MockDID                  *did.Doc
	EncryptionKeyValue       []byte
	EncryptionKeyErr         error
}

// Close previously-opened KMS, removing it if so configured.
func (m *CloseableKMS) Close() error {
	return nil
}

// CreateKeySet create a new public/private encryption and signature key pairs combo.
func (m *CloseableKMS) CreateKeySet() (string, string, error) {
	return m.CreateEncryptionKeyValue, m.CreateSigningKeyValue, m.CreateKeyErr
}

// FindVerKey return a verification key from the list of candidates
func (m *CloseableKMS) FindVerKey(candidateKeys []string) (int, error) {
	return m.FindVerKeyValue, m.FindVerKeyErr
}

// SignMessage sign a message using the private key associated with a given verification key.
func (m *CloseableKMS) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return m.SignMessageValue, m.SignMessageErr
}

// DeriveKEK derives a key encryption key from two keys
// mocked to return empty derived KEK
func (m *CloseableKMS) DeriveKEK(alg, apu, fromKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	return []byte(""), nil
}

// GetEncryptionKey will return the public encryption key corresponding to the public verKey argument
func (m *CloseableKMS) GetEncryptionKey(verKey []byte) ([]byte, error) {
	return m.EncryptionKeyValue, m.EncryptionKeyErr
}

// ConvertToEncryptionKey converts the keypair containing the given verkey to an encryption keypair
func (m *CloseableKMS) ConvertToEncryptionKey(key []byte) ([]byte, error) {
	return m.EncryptionKeyValue, m.EncryptionKeyErr
}
