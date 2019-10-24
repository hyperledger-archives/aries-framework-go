/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto/wallet"
)

// Provider interface for Crypter ctx
type Provider interface {
	CryptoWallet() wallet.Crypto
}

// CrypterCreator method to create new crypter service
type CrypterCreator func(prov Provider) (Crypter, error)

// Crypter is an Aries envelope encrypter to support
// secure DIDComm exchange of envelopes between Aries agents
// TODO create a higher-level crypto that switches implementations based on the algorithm - Issue #273
type Crypter interface {
	// Encrypt a payload in an Aries compliant format using the sender keypair
	// and a list of recipients public keys
	// returns:
	// 		[]byte containing the encrypted envelope
	//		error if encryption failed
	// TODO add key type of recipients and sender keys to be validated by the implementation - Issue #272
	Encrypt(payload []byte, senderKey []byte, recipients [][]byte) ([]byte, error)
	// Decrypt an envelope in an Aries compliant format.
	// 		The recipient's key will be matched from the wallet with the list of recipients in the envelope
	//
	// returns:
	// 		[]byte containing the decrypted payload
	//		error if decryption failed
	// TODO add key type of recipients keys to be validated by the implementation - Issue #272
	Decrypt(envelope []byte) ([]byte, error)
}
