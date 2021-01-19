/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// MockVDR mock implementation of vdr
// to be used only for unit tests.
type MockVDR struct {
	AcceptValue bool
	StoreErr    error
	ReadFunc    func(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error)
	CreateFunc  func(keyManager kms.KeyManager, did *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	CloseErr    error
}

// Read did.
func (m *MockVDR) Read(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

// Create did.
func (m *MockVDR) Create(keyManager kms.KeyManager, didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(keyManager, didDoc, opts...)
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
