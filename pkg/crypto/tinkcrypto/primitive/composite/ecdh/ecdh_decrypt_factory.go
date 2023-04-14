/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
)

// NewECDHDecrypt returns an CompositeDecrypt primitive from the given keyset handle.
func NewECDHDecrypt(h *keyset.Handle) (api.CompositeDecrypt, error) {
	return ecdh.NewECDHDecrypt(h)
}

// NewECDHDecryptWithKeyManager returns an CompositeDecrypt primitive from the given keyset handle and custom key
// manager.
func NewECDHDecryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.CompositeDecrypt, error) {
	return ecdh.NewECDHDecryptWithKeyManager(h, km)
}
