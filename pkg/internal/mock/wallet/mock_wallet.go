/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import "github.com/hyperledger/aries-framework-go/pkg/wallet"

// CloseableWallet mock wallet
type CloseableWallet struct {
	CreateSigningKeyValue wallet.KeyInfo
	CreateSigningKeyErr   error
	SignMessageValue      []byte
	SignMessageErr        error
}

// Close previously-opened wallet, removing it if so configured.
func (m *CloseableWallet) Close() error {
	return nil
}

// CreateSigningKey create a new public/private signing keypair.
func (m *CloseableWallet) CreateSigningKey(metadata map[string]string) (wallet.KeyInfo, error) {
	return m.CreateSigningKeyValue, m.CreateSigningKeyErr
}

// GetSigningKey Fetch info for a signing keypair.
func (m *CloseableWallet) GetSigningKey(verKey string) (wallet.KeyInfo, error) {
	return nil, nil
}

// SignMessage sign a message using the private key associated with a given verification key.
func (m *CloseableWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return m.SignMessageValue, m.SignMessageErr
}

// DecryptMessage decrypt message
func (m *CloseableWallet) DecryptMessage(encMessage []byte, toVerKey string) ([]byte, string, error) {
	return nil, "", nil
}

// PackMessage Pack a message for one or more recipients.
func (m *CloseableWallet) PackMessage(envelope *wallet.Envelope) ([]byte, error) {
	return nil, nil
}

// UnpackMessage Unpack a message.
func (m *CloseableWallet) UnpackMessage(encMessage []byte) (*wallet.Envelope, error) {
	return nil, nil
}

// KeyInfo contains public key and metadata
type KeyInfo struct {
}

// GetVerificationKey return public key
func (m *KeyInfo) GetVerificationKey() string {
	return ""
}

// GetKeyMetadata return metadata
func (m *KeyInfo) GetKeyMetadata() map[string]string {
	return nil
}
