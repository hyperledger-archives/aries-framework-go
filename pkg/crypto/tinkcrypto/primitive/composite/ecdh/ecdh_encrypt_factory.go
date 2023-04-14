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

// NewECDHEncrypt returns an CompositeEncrypt primitive from the given keyset handle.
func NewECDHEncrypt(h *keyset.Handle) (api.CompositeEncrypt, error) {
	return ecdh.NewECDHEncrypt(h)
}

// NewECDHEncryptWithKeyManager returns an CompositeEncrypt primitive from the given h keyset handle and
// custom km key manager.
func NewECDHEncryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.CompositeEncrypt, error) {
	return ecdh.NewECDHEncryptWithKeyManager(h, km)
}
