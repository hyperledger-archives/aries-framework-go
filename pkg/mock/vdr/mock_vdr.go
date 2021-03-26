/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// MockVDR mock implementation of vdr
// to be used only for unit tests.
type MockVDR struct {
	AcceptValue    bool
	StoreErr       error
	ReadFunc       func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	CreateFunc     func(did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	UpdateFunc     func(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error
	DeactivateFunc func(did string, opts ...vdrapi.DIDMethodOption) error
	CloseErr       error
}

// Read did.
func (m *MockVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

// Create did.
func (m *MockVDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(didDoc, opts...)
	}

	return nil, nil
}

// Update did.
func (m *MockVDR) Update(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(didDoc, opts...)
	}

	return nil
}

// Deactivate did.
func (m *MockVDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(didID, opts...)
	}

	return nil
}

// Accept did.
func (m *MockVDR) Accept(method string) bool {
	return m.AcceptValue
}

// Close frees resources being maintained by vdr.
func (m *MockVDR) Close() error {
	return m.CloseErr
}
