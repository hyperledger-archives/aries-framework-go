/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(h *keyset.Handle) (tink.Verifier, error) {
	return NewVerifierWithKeyManager(h, nil /*keyManager*/)
}

// NewVerifierWithKeyManager returns a Verifier primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewVerifierWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.Verifier, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("verifier_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedVerifier(ps)
}

// verifierSet is a Verifier implementation that uses the
// underlying primitive set for verifying.
type wrappedVerifier struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that verifierSet implements the Verifier interface.
var _ tink.Verifier = (*wrappedVerifier)(nil)

func newWrappedVerifier(ps *primitiveset.PrimitiveSet) (*wrappedVerifier, error) {
	if _, ok := (ps.Primary.Primitive).(tink.Verifier); !ok {
		return nil, fmt.Errorf("verifier_factory: not a Verifier primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.Verifier); !ok {
				return nil, fmt.Errorf("verifier_factory: not an Verifier primitive")
			}
		}
	}

	ret := new(wrappedVerifier)
	ret.ps = ps

	return ret, nil
}

var errInvalidSignature = errors.New("verifier_factory: invalid signature")

// Verify checks whether the given signature is a valid signature of the given data.
// nolint:gocyclo
func (v *wrappedVerifier) Verify(signature, data []byte) error {
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(signature) < prefixSize {
		return errInvalidSignature
	}

	// try non-raw keys
	prefix := signature[:prefixSize]
	signatureNoPrefix := signature[prefixSize:]

	entries, err := v.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var signedData []byte
			if entries[i].PrefixType == tinkpb.OutputPrefixType_LEGACY {
				signedData = append(data, byte(0)) //nolint:gocritic
			} else {
				signedData = data
			}

			verifier, ok := (entries[i].Primitive).(tink.Verifier)
			if !ok {
				return fmt.Errorf("verifier_factory: not an Verifier primitive")
			}

			if err = verifier.Verify(signatureNoPrefix, signedData); err == nil {
				return nil
			}
		}
	}

	// try raw keys
	entries, err = v.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			verifier, ok := (entries[i].Primitive).(tink.Verifier)
			if !ok {
				return fmt.Errorf("verifier_factory: not an Verifier primitive")
			}

			if err = verifier.Verify(signature, data); err == nil {
				return nil
			}
		}
	}

	return errInvalidSignature
}
