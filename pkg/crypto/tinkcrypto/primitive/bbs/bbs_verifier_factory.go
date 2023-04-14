/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"

	bbsapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs/api"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(h *keyset.Handle) (bbsapi.Verifier, error) {
	return bbs.NewVerifier(h)
}

// NewVerifierWithKeyManager returns a Verifier primitive from the given keyset handle and custom key manager.
func NewVerifierWithKeyManager(h *keyset.Handle, km registry.KeyManager) (bbsapi.Verifier, error) {
	return bbs.NewVerifierWithKeyManager(h, km)
}
