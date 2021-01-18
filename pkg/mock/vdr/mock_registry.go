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
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/resolve"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
)

// MockVDRegistry mock implementation of vdr
// to be used only for unit tests.
type MockVDRegistry struct {
	CreateErr      error
	CreateValue    *did.Doc
	CreateFunc     func(string, ...create.Option) (*did.DocResolution, error)
	MemStore       map[string]*did.Doc
	StoreFunc      func(*did.Doc) error
	UpdateFunc     func(did string, opts ...update.Option) error
	RecoverFunc    func(did string, opts ...recovery.Option) error
	DeactivateFunc func(did string, opts ...deactivate.Option) error
	PutErr         error
	ResolveErr     error
	ResolveValue   *did.Doc
	ResolveFunc    func(didID string, opts ...resolve.Option) (*did.DocResolution, error)
}

// Store stores the key and the record.
func (m *MockVDRegistry) Store(doc *did.Doc) error {
	k := doc.ID

	if m.StoreFunc != nil {
		return m.StoreFunc(doc)
	}

	if len(m.MemStore) == 0 {
		m.MemStore = make(map[string]*did.Doc)
	}

	m.MemStore[k] = doc

	return m.PutErr
}

// Create mock implementation of create DID.
func (m *MockVDRegistry) Create(method string, opts ...create.Option) (*did.DocResolution, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	if m.CreateFunc != nil {
		return m.CreateFunc(method, opts...)
	}

	doc := m.CreateValue
	if doc == nil {
		doc = createDefaultDID()
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

// Resolve did document.
func (m *MockVDRegistry) Resolve(didID string, opts ...resolve.Option) (*did.DocResolution, error) {
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

// Close frees resources being maintained by vdr.
func (m *MockVDRegistry) Close() error {
	return nil
}

// Update DID Document.
func (m *MockVDRegistry) Update(didID string, opts ...update.Option) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(didID, opts...)
	}

	return nil
}

// Recover DID Document.
func (m *MockVDRegistry) Recover(didID string, opts ...recovery.Option) error {
	if m.RecoverFunc != nil {
		return m.RecoverFunc(didID, opts...)
	}

	return nil
}

// Deactivate DID Document.
func (m *MockVDRegistry) Deactivate(didID string, opts ...deactivate.Option) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(didID, opts...)
	}

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
