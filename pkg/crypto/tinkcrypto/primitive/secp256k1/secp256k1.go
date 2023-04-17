/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1"
)

// This file contains pre-generated KeyTemplates for Signer and Verifier.
// One can use these templates to generate new Keysets.

// DERKeyTemplate is a KeyTemplate that generates a new ECDSA secp256k1 private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: secp256k1
//   - Signature encoding: DER
//   - Output prefix type: TINK
func DERKeyTemplate() (*tinkpb.KeyTemplate, error) {
	return secp256k1.DERKeyTemplate()
}

// IEEEP1363KeyTemplate is a KeyTemplate that generates a new ECDSA secp256k1 private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: secp256k1
//   - Signature encoding: IEEE-P1363
//   - Output prefix type: TINK
func IEEEP1363KeyTemplate() (*tinkpb.KeyTemplate, error) {
	return secp256k1.IEEEP1363KeyTemplate()
}

// NewSigner returns a Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (tink.Signer, error) {
	return secp256k1.NewSigner(h)
}

// NewSignerWithKeyManager returns a Signer primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.Signer, error) {
	return secp256k1.NewSignerWithKeyManager(h, km)
}

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(h *keyset.Handle) (tink.Verifier, error) {
	return secp256k1.NewVerifier(h)
}

// NewVerifierWithKeyManager returns a Verifier primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewVerifierWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.Verifier, error) {
	return secp256k1.NewVerifierWithKeyManager(h, km)
}
