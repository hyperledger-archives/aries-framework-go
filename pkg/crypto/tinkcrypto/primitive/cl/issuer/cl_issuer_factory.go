//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
)

// NewIssuer returns a CL Issuer primitive from the given keyset handle.
func NewIssuer(h *keyset.Handle) (clapi.Issuer, error) {
	return NewIssuerWithKeyManager(h, nil)
}

// NewIssuerWithKeyManager returns a CL Issuer primitive from the given keyset handle and custom key manager.
func NewIssuerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Issuer, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("cl_issuer_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedIssuer(ps)
}

// wrappedIssuer is a CL Issuer implementation that uses the underlying primitive set for CL signing.
type wrappedIssuer struct {
	ps *primitiveset.PrimitiveSet
}

// newWrappedIssuer constructor creates a new wrappedIssuer and checks primitives in ps are all of CL Issuer type.
func newWrappedIssuer(ps *primitiveset.PrimitiveSet) (*wrappedIssuer, error) {
	if _, ok := (ps.Primary.Primitive).(clapi.Issuer); !ok {
		return nil, fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(clapi.Issuer); !ok {
				return nil, fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
			}
		}
	}

	ret := new(wrappedIssuer)
	ret.ps = ps

	return ret, nil
}

func (ws *wrappedIssuer) GetCredentialDefinition() (*clapi.CredentialDefinition, error) {
	primary := ws.ps.Primary

	issuer, ok := (primary.Primitive).(clapi.Issuer)
	if !ok {
		return nil, fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
	}

	return issuer.GetCredentialDefinition()
}

func (ws *wrappedIssuer) CreateCredentialOffer() (*clapi.CredentialOffer, error) {
	primary := ws.ps.Primary

	issuer, ok := (primary.Primitive).(clapi.Issuer)
	if !ok {
		return nil, fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
	}

	return issuer.CreateCredentialOffer()
}

func (ws *wrappedIssuer) IssueCredential(
	values map[string]interface{}, credentialRequest *clapi.CredentialRequest, credOffer *clapi.CredentialOffer,
) (*clapi.Credential, error) {
	primary := ws.ps.Primary

	issuer, ok := (primary.Primitive).(clapi.Issuer)
	if !ok {
		return nil, fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
	}

	return issuer.IssueCredential(values, credentialRequest, credOffer)
}

func (ws *wrappedIssuer) Free() error {
	primary := ws.ps.Primary

	issuer, ok := (primary.Primitive).(clapi.Issuer)
	if !ok {
		return fmt.Errorf("cl_issuer_factory: not a CL Issuer primitive")
	}

	return issuer.Free()
}
