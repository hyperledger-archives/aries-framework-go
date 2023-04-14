//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"

	clapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/api"
)

// NewSigner returns a CL Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (clapi.Signer, error) {
	return signer.NewSigner(h)
}

// NewSignerWithKeyManager returns a CL Signer primitive from the given keyset handle and custom key manager.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Signer, error) {
	return signer.NewSignerWithKeyManager(h, km)
}
