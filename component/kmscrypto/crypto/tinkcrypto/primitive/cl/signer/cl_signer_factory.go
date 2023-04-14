//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	clapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/api"
)

// NewSigner returns a CL Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (clapi.Signer, error) {
	return NewSignerWithKeyManager(h, nil)
}

// NewSignerWithKeyManager returns a CL Signer primitive from the given keyset handle and custom key manager.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Signer, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("cl_signer_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedSigner(ps)
}

// wrappedSigner is a CL Signer implementation that uses the underlying primitive set for CL signing.
type wrappedSigner struct {
	ps *primitiveset.PrimitiveSet
}

// newWrappedSigner constructor creates a new wrappedSigner and checks primitives in ps are all of CL Signer type.
func newWrappedSigner(ps *primitiveset.PrimitiveSet) (*wrappedSigner, error) {
	if _, ok := (ps.Primary.Primitive).(clapi.Signer); !ok {
		return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(clapi.Signer); !ok {
				return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
			}
		}
	}

	ret := new(wrappedSigner)
	ret.ps = ps

	return ret, nil
}

func (ws *wrappedSigner) GetCorrectnessProof() ([]byte, error) {
	primary := ws.ps.Primary

	signer, ok := (primary.Primitive).(clapi.Signer)
	if !ok {
		return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	return signer.GetCorrectnessProof()
}

func (ws *wrappedSigner) Sign(
	values map[string]interface{},
	secrets []byte,
	correctnessProof []byte,
	nonces [][]byte,
	did string,
) ([]byte, []byte, error) {
	primary := ws.ps.Primary

	signer, ok := (primary.Primitive).(clapi.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	return signer.Sign(values, secrets, correctnessProof, nonces, did)
}

func (ws *wrappedSigner) Free() error {
	primary := ws.ps.Primary

	signer, ok := (primary.Primitive).(clapi.Signer)
	if !ok {
		return fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	return signer.Free()
}
