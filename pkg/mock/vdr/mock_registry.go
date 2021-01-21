/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// MockVDRegistry mock implementation of vdr
// to be used only for unit tests.
type MockVDRegistry struct {
	CreateErr      error
	CreateValue    *did.Doc
	CreateFunc     func(string, *did.Doc, ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
	UpdateFunc     func(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error
	DeactivateFunc func(did string, opts ...vdrapi.DIDMethodOption) error
	ResolveErr     error
	ResolveValue   *did.Doc
	ResolveFunc    func(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error)
}

// Create mock implementation of create DID.
func (m *MockVDRegistry) Create(method string, didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	if m.CreateFunc != nil {
		return m.CreateFunc(method, didDoc, opts...)
	}

	doc := m.CreateValue
	if doc == nil {
		doc = createDefaultDID()
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

// Resolve did document.
func (m *MockVDRegistry) Resolve(didID string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error) {
	if m.ResolveFunc != nil {
		return m.ResolveFunc(didID, opts...)
	}

	if m.ResolveErr != nil {
		return nil, m.ResolveErr
	}

	if m.ResolveValue == nil {
		return nil, vdrapi.ErrNotFound
	}

	return &did.DocResolution{DIDDocument: m.ResolveValue}, nil
}

// Update did.
func (m *MockVDRegistry) Update(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(didDoc, opts...)
	}

	return nil
}

// Deactivate did.
func (m *MockVDRegistry) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(didID, opts...)
	}

	return nil
}

// Close frees resources being maintained by vdr.
func (m *MockVDRegistry) Close() error {
	return nil
}

func createDefaultDID() *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		didID      = "did:local:abc"
		creator    = didID + "#key-1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: "https://agent.example.com/",
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:            []string{didContext},
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{signingKey},
		Service:            []did.Service{service},
		Created:            &createdTime,
	}
}
