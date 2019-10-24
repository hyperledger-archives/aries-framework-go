/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	secretwallet "github.com/hyperledger/aries-framework-go/pkg/crypto/internal/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// provider contains dependencies for the base wallet and is typically created by using aries.Context()
type provider interface {
	StorageProvider() storage.Provider
	InboundTransportEndpoint() string
}

// BaseWallet wallet implementation
type BaseWallet struct {
	secretWallet CloseableWallet
}

// New return new instance of wallet implementation
func New(ctx provider) (*BaseWallet, error) {
	w, err := secretwallet.New(ctx)
	if err != nil {
		return nil, err
	}
	return &BaseWallet{
		secretWallet: w,
	}, nil
}

// CreateEncryptionKey create a new public/private encryption keypair.
func (w *BaseWallet) CreateEncryptionKey() (string, error) {
	return w.secretWallet.CreateEncryptionKey()
}

// CreateSigningKey create a new public/private signing keypair.
func (w *BaseWallet) CreateSigningKey() (string, error) {
	return w.secretWallet.CreateSigningKey()
}

// SignMessage sign a message using the private key associated with a given verification key.
func (w *BaseWallet) SignMessage(message []byte, fromVerKey string) ([]byte, error) {
	return w.secretWallet.SignMessage(message, fromVerKey)
}

// AttachCryptoOperator attaches a crypto operator to this wallet, so the operator can use its private keys.
func (w *BaseWallet) AttachCryptoOperator(cryptoOp operator.CryptoOperator) error {
	return w.secretWallet.AttachCryptoOperator(cryptoOp)
}

// Close wallet
func (w *BaseWallet) Close() error {
	return w.secretWallet.Close()
}

// CreateDID returns new DID Document
func (w *BaseWallet) CreateDID(method string, opts ...didcreator.DocOpts) (*did.Doc, error) {
	return w.secretWallet.CreateDID(method, opts...)
}

// GetDID gets already created DID document from underlying store
func (w *BaseWallet) GetDID(id string) (*did.Doc, error) {
	return w.secretWallet.GetDID(id)
}

// DeriveKEK will derive an ephemeral symmetric key (kek) using a private key fetched from
// the wallet corresponding to fromPubKey and derived with toPubKey
// This implementation is for curve 25519 only
func (w *BaseWallet) DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error) { // nolint:lll
	return w.secretWallet.DeriveKEK(alg, apu, fromPubKey, toPubKey)
}

// FindVerKey selects a signing key which is present in candidateKeys that is present in the wallet
func (w *BaseWallet) FindVerKey(candidateKeys []string) (int, error) {
	return w.secretWallet.FindVerKey(candidateKeys)
}
