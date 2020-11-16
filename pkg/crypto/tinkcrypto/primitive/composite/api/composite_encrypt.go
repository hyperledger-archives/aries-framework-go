/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// package api provides the composite primitive interfaces. These will be mainly used as the crypto primitives for
// building protected JWE messages.

// CompositeEncrypt will encrypt a `plaintext` using AEAD primitive (with ECDH-ES cek key wrapping by recipient executed
// externally). It returns the resulting serialized JWE []byte. This type is used mainly for repudiation requests where
// the sender identity remains unknown to the recipient in a serialized EncryptedData envelope (used mainly to build JWE
// messages).
type CompositeEncrypt interface {
	// Encrypt operation: encrypts plaintext with aad for a given cek.
	// Returns resulting EncryptedData wrapping ciphertext content or error if failed.
	Encrypt(plainText, aad []byte) ([]byte, error)
}
