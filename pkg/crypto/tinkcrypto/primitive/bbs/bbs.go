/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbs provides implementations of BBS+ key management and primitives.
//
// The functionality of BBS+ signatures/proofs is represented as a pair of
// primitives (interfaces):
//
//  * Signer for signing a list of messages with a private key
//
//  * Verifier for verifying a signature against a list of messages, deriving a proof from a signature for a given
//    message and verifying such derived proof.
package bbs

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton.
	err := registry.RegisterKeyManager(newBBSSignerKeyManager())
	if err != nil {
		panic(fmt.Sprintf("bbs.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newBBSVerifierKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}
}
