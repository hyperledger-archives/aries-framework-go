//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package prover

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
)

// NewProver returns a CL Prover primitive from the given keyset handle.
func NewProver(h *keyset.Handle) (clapi.Prover, error) {
	return NewProverWithKeyManager(h, nil)
}

// NewProverWithKeyManager returns a CL Prover primitive from the given keyset handle and custom key manager.
func NewProverWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Prover, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("cl_prover_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedProver(ps)
}

// wrappedProver is a CL Prover implementation that uses the underlying primitive set for CL prover.
type wrappedProver struct {
	ps *primitiveset.PrimitiveSet
}

// newWrappedProver constructor creates a new wrappedProver and checks primitives in ps are all of CL Prover type.
func newWrappedProver(ps *primitiveset.PrimitiveSet) (*wrappedProver, error) {
	if _, ok := (ps.Primary.Primitive).(clapi.Prover); !ok {
		return nil, fmt.Errorf("cl_prover_factory: not a CL Prover primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(clapi.Prover); !ok {
				return nil, fmt.Errorf("cl_prover_factory: not a CL Prover primitive")
			}
		}
	}

	ret := new(wrappedProver)
	ret.ps = ps

	return ret, nil
}

func (ws *wrappedProver) CreateCredentialRequest(
	credOffer *clapi.CredentialOffer, credDef *clapi.CredentialDefinition, proverId string,
) (*clapi.CredentialRequest, error) {
	primary := ws.ps.Primary

	prover, ok := (primary.Primitive).(clapi.Prover)
	if !ok {
		return nil, fmt.Errorf("cl_prover_factory: not a CL Prover primitive")
	}

	return prover.CreateCredentialRequest(credOffer, credDef, proverId)
}

func (ws *wrappedProver) ProcessCredential(
	credential *clapi.Credential, credRequest *clapi.CredentialRequest, credDef *clapi.CredentialDefinition,
) error {
	primary := ws.ps.Primary

	prover, ok := (primary.Primitive).(clapi.Prover)
	if !ok {
		return fmt.Errorf("cl_prover_factory: not a CL Prover primitive")
	}

	return prover.ProcessCredential(credential, credRequest, credDef)
}

func (ws *wrappedProver) CreateProof(
	presentationRequest *clapi.PresentationRequest, credentials []*clapi.Credential, credDefs []*clapi.CredentialDefinition,
) (*clapi.Proof, error) {
	primary := ws.ps.Primary

	prover, ok := (primary.Primitive).(clapi.Prover)
	if !ok {
		return nil, fmt.Errorf("cl_prover_factory: not a CL Prover primitive")
	}

	return prover.CreateProof(presentationRequest, credentials, credDefs)
}

func (ws *wrappedProver) Free() error {
	primary := ws.ps.Primary

	prover, ok := (primary.Primitive).(clapi.Prover)
	if !ok {
		return fmt.Errorf("cl_prover_factory: not a CL Issuer primitive")
	}

	return prover.Free()
}
