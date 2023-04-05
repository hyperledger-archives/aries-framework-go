/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// Package secp256k1 provides implementations of the Signer and Verifier
// primitives.
//
// To sign data using Tink you can use the Secp256k1 key templates.
// nolint:gochecknoinits
func init() {
	// ECDSA Secp256K1 key managers.
	if err := registry.RegisterKeyManager(newSecp256K2SignerKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}

	if err := registry.RegisterKeyManager(newSecp256K1VerifierKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
}
