/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	chacha "golang.org/x/crypto/chacha20poly1305"
)

// Crypter is an Aries envelope encrypter to support
// secure DIDComm exchange of envelopes between Aries agents
type Crypter interface {
	// Encrypt a payload in an Aries compliant format using the sender keypair
	// and a list of recipients public keys
	// returns:
	// 		[]byte containing the encrypted envelope
	//		error if encryption failed
	Encrypt(payload []byte, sender KeyPair, recipients []*[chacha.KeySize]byte) ([]byte, error)
	// Decrypt an envelope in an Aries compliant format with the recipient's private key
	// and the recipient's public key both set in recipientKeyPair
	// returns:
	// 		[]byte containing the decrypted payload
	//		error if decryption failed
	Decrypt(envelope []byte, recipientKeyPair KeyPair) ([]byte, error)
}

// KeyPair represents a private/public key pair each with 32 bytes in size
type KeyPair struct {
	// Priv is a private key
	Priv *[chacha.KeySize]byte
	// Pub is a public key
	Pub *[chacha.KeySize]byte
}

// IsKeyPairValid is a utility function that validates a KeyPair
func IsKeyPairValid(kp KeyPair) bool {
	if kp.Priv == nil || kp.Pub == nil {
		return false
	}

	return true
}
