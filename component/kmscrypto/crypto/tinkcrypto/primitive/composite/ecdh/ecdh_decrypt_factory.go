/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
)

// NewECDHDecrypt returns an CompositeDecrypt primitive from the given keyset handle.
func NewECDHDecrypt(h *keyset.Handle) (api.CompositeDecrypt, error) {
	return NewECDHDecryptWithKeyManager(h, nil /*keyManager*/)
}

// NewECDHDecryptWithKeyManager returns an CompositeDecrypt primitive from the given keyset handle and custom key
// manager.
func NewECDHDecryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.CompositeDecrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdh_factory: cannot obtain primitive set: %w", err)
	}

	return newDecryptPrimitiveSet(ps)
}

// decryptPrimitiveSet is an CompositeDecrypt implementation that uses the underlying primitive set for
// decryption.
type decryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the CompositeDecrypt interface.
var _ api.CompositeDecrypt = (*decryptPrimitiveSet)(nil)

func newDecryptPrimitiveSet(ps *primitiveset.PrimitiveSet) (*decryptPrimitiveSet, error) {
	if _, ok := (ps.Primary.Primitive).(api.CompositeDecrypt); !ok {
		return nil, errors.New("ecdh_factory: not a CompositeDecrypt primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(api.CompositeDecrypt); !ok {
				return nil, errors.New("ecdh_factory: not a CompositeDecrypt primitive")
			}
		}
	}

	ret := new(decryptPrimitiveSet)
	ret.ps = ps

	return ret, nil
}

func (a *decryptPrimitiveSet) entries(ct []byte) map[string][]*primitiveset.Entry {
	cipherEntries := make(map[string][]*primitiveset.Entry)

	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ct) > prefixSize {
		if entries, err := a.ps.EntriesForPrefix(string(ct[:prefixSize])); err == nil {
			cipherEntries[string(ct[prefixSize:])] = entries
		}
	}

	if entries, err := a.ps.RawEntries(); err == nil {
		cipherEntries[string(ct)] = entries
	}

	return cipherEntries
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *decryptPrimitiveSet) Decrypt(ct, aad []byte) ([]byte, error) {
	for cipher, entries := range a.entries(ct) {
		for _, e := range entries {
			p, ok := (e.Primitive).(api.CompositeDecrypt)
			if !ok {
				return nil, errors.New("ecdh_factory: not a CompositeDecrypt primitive")
			}

			pt, e := p.Decrypt([]byte(cipher), aad)
			if e == nil {
				return pt, nil
			}
		}
	}

	// nothing worked
	return nil, errors.New("ecdh_factory: decryption failed")
}
