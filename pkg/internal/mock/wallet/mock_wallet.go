/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/envelope"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// CloseableWallet mock wallet
type CloseableWallet struct {
	CreateEncryptionKeyValue string
	CreateEncryptionKeyErr   error
	CreateSigningKeyValue    string
	CreateSigningKeyErr      error
	FindVerKeyValue          int
	FindVerKeyErr            error
	SignMessageValue         []byte
	SignMessageErr           error
	DecryptMessageValue      []byte
	DecryptMessageErr        error
	PackValue                []byte
	PackErr                  error
	UnpackValue              *envelope.Envelope
	UnpackErr                error
	MockDID                  *did.Doc
}

// Close previously-opened wallet, removing it if so configured.
func (m *CloseableWallet) Close() error {
	return nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (m *CloseableWallet) CreateEncryptionKey() (string, error) {
	return m.CreateEncryptionKeyValue, m.CreateEncryptionKeyErr
}

// CreateSigningKey create a new public/private signing keypair.
func (m *CloseableWallet) CreateSigningKey() (string, error) {
	return m.CreateSigningKeyValue, m.CreateSigningKeyErr
}

// FindVerKey return a verification key from the list of candidates
func (m *CloseableWallet) FindVerKey(candidateKeys []string) (int, error) {
	return m.FindVerKeyValue, m.FindVerKeyErr
}

// SignMessage sign a message using the private key associated with a given verification key.
func (m *CloseableWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return m.SignMessageValue, m.SignMessageErr
}

// DeriveKEK derives a key encryption key from two keys
// mocked to return empty derived KEK
func (m *CloseableWallet) DeriveKEK(alg, apu, fromKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	return []byte(""), nil
}

// CreateDID returns new DID Document
func (m *CloseableWallet) CreateDID(method string, opts ...wallet.DocOpts) (*did.Doc, error) {
	return m.MockDID, nil
}

// GetDID gets already created DID document by ID.
func (m *CloseableWallet) GetDID(id string) (*did.Doc, error) {
	return m.MockDID, nil
}
