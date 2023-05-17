/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrapi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// VDR mock implementation of vdr
// to be used only for unit tests.
type VDR struct {
	AcceptValue    bool
	StoreErr       error
	AcceptFunc     func(method string, opts ...vdrapi.DIDMethodOption) bool
	ReadFunc       func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	CreateFunc     func(did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	UpdateFunc     func(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error
	DeactivateFunc func(did string, opts ...vdrapi.DIDMethodOption) error
	CloseErr       error
}

// Read did.
func (m *VDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

// Create did.
func (m *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(didDoc, opts...)
	}

	return nil, nil
}

// Update did.
func (m *VDR) Update(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(didDoc, opts...)
	}

	return nil
}

// Deactivate did.
func (m *VDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(didID, opts...)
	}

	return nil
}

// Accept did.
func (m *VDR) Accept(method string, opts ...vdrapi.DIDMethodOption) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(method, opts...)
	}

	return m.AcceptValue
}

// Close frees resources being maintained by vdr.
func (m *VDR) Close() error {
	return m.CloseErr
}
