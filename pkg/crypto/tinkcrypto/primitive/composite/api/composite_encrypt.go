/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// CompositeEncrypt will encrypt a `plaintext` using AEAD primitive and ECDH-ES key wrapping by recipient
// It returns the resulting serialized JWE []byte. This type is used mainly for repudiation requests where the sender
// identity remains unknown to the recipient in a serialized EncryptedData envelope (used mainly to build JWE messages).
type CompositeEncrypt interface {
	// Encrypt operation: encrypts plaintext with aad represented as the list of recipient's corresponding public keys
	// Returns resulting EncryptedData wrapping ciphertext and the recipients protected keys or error if failed.
	Encrypt(plainText, aad []byte) ([]byte, error)
}
