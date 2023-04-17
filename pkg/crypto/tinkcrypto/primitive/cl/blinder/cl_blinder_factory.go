//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
)

// NewBlinder returns a CL Blinder primitive from the given keyset handle.
func NewBlinder(h *keyset.Handle) (clapi.Blinder, error) {
	return blinder.NewBlinder(h)
}

// NewBlinderWithKeyManager returns a CL Blinder primitive from the given keyset handle and custom key manager.
func NewBlinderWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Blinder, error) {
	return blinder.NewBlinderWithKeyManager(h, km)
}
