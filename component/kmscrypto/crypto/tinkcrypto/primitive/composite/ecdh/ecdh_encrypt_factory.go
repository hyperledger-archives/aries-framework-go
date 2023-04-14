/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
)

// NewECDHEncrypt returns an CompositeEncrypt primitive from the given keyset handle.
func NewECDHEncrypt(h *keyset.Handle) (api.CompositeEncrypt, error) {
	return NewECDHEncryptWithKeyManager(h, nil /*keyManager*/)
}

// NewECDHEncryptWithKeyManager returns an CompositeEncrypt primitive from the given h keyset handle and
// custom km key manager.
func NewECDHEncryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.CompositeEncrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdh_factory: cannot obtain primitive set: %w", err)
	}

	return newEncryptPrimitiveSet(ps)
}

// encryptPrimitiveSet is an CompositeEncrypt implementation that uses the underlying primitive set for encryption.
type encryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the CompositeEncrypt interface.
var _ api.CompositeEncrypt = (*encryptPrimitiveSet)(nil)

func newEncryptPrimitiveSet(ps *primitiveset.PrimitiveSet) (*encryptPrimitiveSet, error) {
	if _, ok := (ps.Primary.Primitive).(api.CompositeEncrypt); !ok {
		return nil, errors.New("ecdh_factory: not a CompositeEncrypt primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(api.CompositeEncrypt); !ok {
				return nil, errors.New("ecdh_factory: not a CompositeEncrypt primitive")
			}
		}
	}

	ret := new(encryptPrimitiveSet)
	ret.ps = ps

	return ret, nil
}

// Encrypt encrypts the given plaintext using the recipient public key found in the enclosed primitive.
// It returns the ciphertext being a serialized JWE []byte.
func (a *encryptPrimitiveSet) Encrypt(pt, aad []byte) ([]byte, error) {
	primary := a.ps.Primary

	p, ok := (primary.Primitive).(api.CompositeEncrypt)
	if !ok {
		return nil, errors.New("ecdh_factory: not a CompositeEncrypt primitive")
	}

	return p.Encrypt(pt, aad)
}
