/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2020

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// NewPublicKeyVerifier creates a signature verifier that verifies a Ed25519 signature
// taking Ed25519 public key bytes as input.
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return verifier.NewPublicKeyVerifier(verifier.NewEd25519SignatureVerifier())
}
