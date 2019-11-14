/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// MockVDRIRegistry mock implementation of vdri
// to be used only for unit tests
type MockVDRIRegistry struct {
	CreateErr    error
	CreateValue  *did.Doc
	MemStore     map[string]*did.Doc
	PutErr       error
	ResolveErr   error
	ResolveValue *did.Doc
}

// Store stores the key and the record
func (m *MockVDRIRegistry) Store(doc *did.Doc) error {
	k := doc.ID

	if len(m.MemStore) == 0 {
		m.MemStore = make(map[string]*did.Doc)
	}

	m.MemStore[k] = doc

	return m.PutErr
}

// Create mock implementation of create DID
func (m *MockVDRIRegistry) Create(method string, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	doc := m.CreateValue
	if doc == nil {
		doc = createDefaultDID()
	}

	return doc, nil
}

// Resolve did document
func (m *MockVDRIRegistry) Resolve(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
	if m.ResolveErr != nil {
		return nil, m.ResolveErr
	}

	if m.ResolveValue == nil {
		return nil, errors.New("not found")
	}

	return m.ResolveValue, nil
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
	}

	signingKey := did.PublicKey{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:   []string{didContext},
		ID:        didID,
		PublicKey: []did.PublicKey{signingKey},
		Service:   []did.Service{service},
		Created:   &createdTime,
	}
}
