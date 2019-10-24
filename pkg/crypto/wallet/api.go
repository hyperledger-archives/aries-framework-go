/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/operator"
)

// Wallet interface
type Wallet interface {
	Crypto
	Signer
	didcreator.DIDCreator
}

// CloseableWallet interface for wallets that can be closed
type CloseableWallet interface {
	io.Closer
	Wallet
}

// Crypto interface
type Crypto interface {

	// CreateEncryptionKey create a new public/private encryption keypair.
	//
	// Returns:
	//
	// string: verKey
	//
	// error: error
	CreateEncryptionKey() (string, error)

	// CreateSigningKey create a new public/private signing keypair.
	//
	// Returns:
	//
	// string: verKey
	//
	// error: error
	CreateSigningKey() (string, error)

	// DeriveKEK will derive an ephemeral symmetric key (kek) using a private from key fetched from
	// from the wallet corresponding to fromPubKey and derived with toPubKey.
	//
	// This function assumes both fromPubKey and toPubKey to be on curve25519.
	//
	// returns:
	// 		kek []byte the key encryption key used to decrypt a cek (a shared key)
	//		error in case of errors
	DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error)

	// FindVerKey will search the wallet to find stored keys that match any of candidateKeys and
	// 		return the index of the first match
	// returns:
	// 		int index of candidateKeys that matches the first key found in the wallet
	//		error in case of errors (including ErrKeyNotFound)
	//
	//		in case of error, the index will be -1
	FindVerKey(candidateKeys []string) (int, error)

	// AttachCryptoOperator attaches a crypto operator to this wallet, so the operator can use its private keys.
	AttachCryptoOperator(cryptoOp operator.CryptoOperator) error
}

// Signer interface provides signing capabilities
type Signer interface {

	// SignMessage sign a message using the private key associated with a given verification key.
	//
	// Args:
	//
	// message: The message to sign
	//
	// fromVerKey: Sign using the private key related to this verification key
	//
	// Returns:
	//
	// []byte: The signature
	//
	// error: error
	SignMessage(message []byte, fromVerKey string) ([]byte, error)
}
