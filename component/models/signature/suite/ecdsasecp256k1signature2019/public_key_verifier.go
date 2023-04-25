/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsasecp256k1signature2019

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// NewPublicKeyVerifier creates a signature verifier that verifies a ECDSA secp256k1 signature
// taking Ed25519 public key bytes as input.
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return verifier.NewPublicKeyVerifier(
		verifier.NewECDSASecp256k1SignatureVerifier(),
		verifier.WithExactPublicKeyType(jwkType))
}
