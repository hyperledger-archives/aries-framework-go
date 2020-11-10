/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

// Signer defines generic signer.
type Signer interface {
	// Sign signs the message.
	Sign(msg []byte) ([]byte, error)

	// PublicKey returns a public key object (e.g. ed25519.VerificationMethod or *ecdsa.PublicKey).
	PublicKey() interface{}

	// PublicKeyBytes returns bytes of the public key.
	PublicKeyBytes() []byte
}
