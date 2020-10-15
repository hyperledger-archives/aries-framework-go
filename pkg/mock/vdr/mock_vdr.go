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
	AcceptValue bool
	StoreErr    error
	ReadFunc    func(didID string, opts ...vdrapi.ResolveOpts) (*did.Doc, error)
	BuildFunc   func(pubKey *vdrapi.PubKey, opts ...vdrapi.DocOpts) (*did.Doc, error)
	CloseErr    error
}

// Read did.
func (m *MockVDR) Read(didID string, opts ...vdrapi.ResolveOpts) (*did.Doc, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

// Store did.
func (m *MockVDR) Store(doc *did.Doc, by *[]vdrapi.ModifiedBy) error {
	return m.StoreErr
}

// Build did.
func (m *MockVDR) Build(pubKey *vdrapi.PubKey, opts ...vdrapi.DocOpts) (*did.Doc, error) {
	if m.BuildFunc != nil {
		return m.BuildFunc(pubKey, opts...)
	}

	return nil, nil
}

// Accept did.
func (m *MockVDR) Accept(method string) bool {
	return m.AcceptValue
}

// Close frees resources being maintained by vdr.
func (m *MockVDR) Close() error {
	return m.CloseErr
}
