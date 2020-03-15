/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2018

import (
	"crypto/ed25519"
	"errors"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// PublicKeyVerifier verifies a Ed25519 signature taking Ed25519 public key bytes as input.
// NOTE: this verifier is present for backward compatibility reasons and can be removed soon.
// Please use CryptoVerifier or your own verifier.
type PublicKeyVerifier struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifier) Verify(pubKey *sigverifier.PublicKey, doc, signature []byte) error {
	// ed25519 panics if key size is wrong
	if len(pubKey.Value) != ed25519.PublicKeySize {
		return errors.New("ed25519: invalid key")
	}

	verified := ed25519.Verify(pubKey.Value, doc, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}
