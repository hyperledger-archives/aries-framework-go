/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
)

// NewSigner returns a Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (tink.Signer, error) {
	return NewSignerWithKeyManager(h, nil /*keyManager*/)
}

// NewSignerWithKeyManager returns a Signer primitive from the given keyset handle and custom key manager.
// Deprecated: register the KeyManager and use New above.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.Signer, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("public_key_sign_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedSigner(ps)
}

// wrappedSigner is an Signer implementation that uses the underlying primitive set for signing.
type wrappedSigner struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that wrappedSigner implements the Signer interface.
var _ tink.Signer = (*wrappedSigner)(nil)

func newWrappedSigner(ps *primitiveset.PrimitiveSet) (*wrappedSigner, error) {
	if _, ok := (ps.Primary.Primitive).(tink.Signer); !ok {
		return nil, fmt.Errorf("public_key_sign_factory: not a Signer primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(tink.Signer); !ok {
				return nil, fmt.Errorf("public_key_sign_factory: not an Signer primitive")
			}
		}
	}

	ret := new(wrappedSigner)
	ret.ps = ps

	return ret, nil
}

// Sign signs the given data and returns the signature concatenated with the identifier of the
// primary primitive.
func (s *wrappedSigner) Sign(data []byte) ([]byte, error) {
	primary := s.ps.Primary

	signer, ok := (primary.Primitive).(tink.Signer)
	if !ok {
		return nil, fmt.Errorf("public_key_sign_factory: not a Signer primitive")
	}

	var signedData []byte
	if primary.PrefixType == tinkpb.OutputPrefixType_LEGACY {
		signedData = append(signedData, data...)
		signedData = append(signedData, byte(0))
	} else {
		signedData = data
	}

	signature, err := signer.Sign(signedData)
	if err != nil {
		return nil, err
	}

	return append([]byte(primary.Prefix), signature...), nil
}
