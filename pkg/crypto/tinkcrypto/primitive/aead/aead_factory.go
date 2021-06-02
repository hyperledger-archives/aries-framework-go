/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// New returns an AEAD primitive from the given keyset handle.
func New(h *keyset.Handle) (tink.AEAD, error) {
	return NewWithKeyManager(h, nil /*keyManager*/)
}

// NewWithKeyManager returns an AEAD primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.AEAD, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedAead(ps)
}

// wrappedAead is an AEAD implementation that uses the underlying primitive set for encryption
// and decryption.
type wrappedAead struct {
	ps *primitiveset.PrimitiveSet
}

func newWrappedAead(ps *primitiveset.PrimitiveSet) (*wrappedAead, error) {
	if _, ok := (ps.Primary.Primitive).(tink.AEAD); !ok {
		return nil, errors.New("aead_factory: not an AEAD primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.AEAD); !ok {
				return nil, errors.New("aead_factory: not an AEAD primitive")
			}
		}
	}

	ret := new(wrappedAead)
	ret.ps = ps

	return ret, nil
}

// Encrypt encrypts the given plaintext with the given additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *wrappedAead) Encrypt(pt, ad []byte) ([]byte, error) {
	primary := a.ps.Primary

	p, ok := (primary.Primitive).(tink.AEAD)
	if !ok {
		return nil, errors.New("aead_factory: Encrypt() - not an AEAD primitive")
	}

	ct, err := p.Encrypt(pt, ad)
	if err != nil {
		return nil, fmt.Errorf("aead_factory: Encrypt() - %w", err)
	}

	return append([]byte(primary.Prefix), ct...), nil
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *wrappedAead) Decrypt(ct, aad []byte) ([]byte, error) {
	for cipher, entries := range a.entries(ct) {
		for _, e := range entries {
			p, ok := (e.Primitive).(tink.AEAD)
			if !ok {
				return nil, errors.New("aead_factory: Decrypt() - not an AEAD primitive")
			}

			pt, e := p.Decrypt([]byte(cipher), aad)
			if e == nil {
				return pt, nil
			}
		}
	}

	// nothing worked
	return nil, errors.New("aead_factory: Decrypt() - decryption failed")
}

func (a *wrappedAead) entries(ct []byte) map[string][]*primitiveset.Entry {
	cipherEntries := make(map[string][]*primitiveset.Entry)

	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ct) > prefixSize {
		if entries, err := a.ps.EntriesForPrefix(string(ct[:prefixSize])); err == nil {
			cipherEntries[string(ct[prefixSize:])] = entries
		}
	}

	// add raw entries
	if entries, err := a.ps.RawEntries(); err == nil {
		cipherEntries[string(ct)] = entries
	}

	return cipherEntries
}
