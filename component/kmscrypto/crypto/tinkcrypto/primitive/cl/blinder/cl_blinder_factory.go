//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blinder

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	clapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/api"
)

// NewBlinder returns a CL Blinder primitive from the given keyset handle.
func NewBlinder(h *keyset.Handle) (clapi.Blinder, error) {
	return NewBlinderWithKeyManager(h, nil)
}

// NewBlinderWithKeyManager returns a CL Blinder primitive from the given keyset handle and custom key manager.
func NewBlinderWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Blinder, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("cl_blinder_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedBlinder(ps)
}

// wrappedBlinder is a CL Blinder implementation that uses the underlying primitive set for CL blinder.
type wrappedBlinder struct {
	ps *primitiveset.PrimitiveSet
}

// newWrappedBlinder constructor creates a new wrappedBlinder and checks primitives in ps are all of CL Blinder type.
func newWrappedBlinder(ps *primitiveset.PrimitiveSet) (*wrappedBlinder, error) {
	if _, ok := (ps.Primary.Primitive).(clapi.Blinder); !ok {
		return nil, fmt.Errorf("cl_blinder_factory: not a CL Blinder primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(clapi.Blinder); !ok {
				return nil, fmt.Errorf("cl_blinder_factory: not a CL Blinder primitive")
			}
		}
	}

	ret := new(wrappedBlinder)
	ret.ps = ps

	return ret, nil
}

func (ws *wrappedBlinder) Blind(
	values map[string]interface{},
) ([]byte, error) {
	primary := ws.ps.Primary

	blinder, ok := (primary.Primitive).(clapi.Blinder)
	if !ok {
		return nil, fmt.Errorf("cl_blinder_factory: not a CL Blinder primitive")
	}

	return blinder.Blind(values)
}

func (ws *wrappedBlinder) Free() error {
	primary := ws.ps.Primary

	blinder, ok := (primary.Primitive).(clapi.Blinder)
	if !ok {
		return fmt.Errorf("cl_blinder_factory: not a CL Issuer primitive")
	}

	return blinder.Free()
}
