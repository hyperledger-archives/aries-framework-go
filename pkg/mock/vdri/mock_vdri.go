/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// MockVDRI mock implementation of vdri
// to be used only for unit tests.
type MockVDRI struct {
	AcceptValue bool
	StoreErr    error
	ReadFunc    func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error)
	BuildFunc   func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error)
	CloseErr    error
}

// Read did.
func (m *MockVDRI) Read(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

// Store did.
func (m *MockVDRI) Store(doc *did.Doc, by *[]vdriapi.ModifiedBy) error {
	return m.StoreErr
}

// Build did.
func (m *MockVDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	if m.BuildFunc != nil {
		return m.BuildFunc(pubKey, opts...)
	}

	return nil, nil
}

// Accept did.
func (m *MockVDRI) Accept(method string) bool {
	return m.AcceptValue
}

// Close frees resources being maintained by vdri.
func (m *MockVDRI) Close() error {
	return m.CloseErr
}
