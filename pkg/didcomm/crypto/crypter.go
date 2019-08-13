/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import "golang.org/x/crypto/chacha20poly1305"

// Crypter is an Aries envelope encrypter to support
// secure DIDComm exchange of envelopes between Aries agents
type Crypter interface {
	// Encrypt a payload in an Aries compliant format
	// returns:
	// 		[]byte containing the encrypted envelope
	//		error if encryption failed
	Encrypt(payload []byte) ([]byte, error)
	// Decrypt an envelope in an Aries compliant format
	// returns:
	// 		[]byte containing the decrypted payload
	//		error if encryption failed
	Decrypt(envelope []byte, recipientPrivKey *[chacha20poly1305.KeySize]byte) ([]byte, error)
}
