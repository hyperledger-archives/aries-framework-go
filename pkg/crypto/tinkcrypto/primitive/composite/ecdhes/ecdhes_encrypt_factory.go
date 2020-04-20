/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
)

// NewECDHESEncrypt returns an CompositeEncrypt primitive from the given keyset handle.
func NewECDHESEncrypt(h *keyset.Handle) (api.CompositeEncrypt, error) {
	return NewECDHESEncryptWithKeyManager(h, nil /*keyManager*/)
}

// NewECDHESEncryptWithKeyManager returns an CompositeEncrypt primitive from the given h keyset handle and
// custom km key manager.
func NewECDHESEncryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.CompositeEncrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_factory: cannot obtain primitive set: %s", err)
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
		return nil, fmt.Errorf("ecdhes_factory: not an CompositeEncrypt primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(api.CompositeEncrypt); !ok {
				return nil, fmt.Errorf("ecdhes_factory: not an CompositeEncrypt primitive")
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
		return nil, fmt.Errorf("ecdhes_factory: not an CompositeEncrypt primitive")
	}

	ct, err := p.Encrypt(pt, aad)
	if err != nil {
		return nil, err
	}

	return ct, nil
}
