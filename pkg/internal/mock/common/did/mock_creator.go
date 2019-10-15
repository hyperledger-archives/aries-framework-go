/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// MockDIDCreator mock implementation of DID creator
// to be used only for unit tests
type MockDIDCreator struct {
	Failure error
	Doc     *did.Doc
	Store   storage.Store
}

// CreateDID mock implementation of create DID
func (m *MockDIDCreator) CreateDID(opts ...wallet.DocOpts) (*did.Doc, error) {
	if m.Failure != nil {
		return nil, m.Failure
	}

	doc := m.Doc
	if doc == nil {
		doc = createDefaultDID()
		if m.Store != nil {
			err := persistDID(m.Store, doc.ID, doc)
			if err != nil {
				return nil, err
			}
		}
	}

	return doc, nil
}

// GetDID mock implementation of get DID
func (m *MockDIDCreator) GetDID(id string) (*did.Doc, error) {
	if m.Failure != nil {
		return nil, m.Failure
	}

	if m.Doc != nil {
		return m.Doc, nil
	}

	if m.Store != nil {
		return getDID(m.Store, id)
	}

	return nil, storage.ErrDataNotFound
}

func createDefaultDID() *did.Doc {
	const didContext = "https://w3id.org/did/v1"
	const didID = "did:local:abc"
	const creator = didID + "#key-1"
	const keyType = "Ed25519VerificationKey2018"

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
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
		Created:   &createdTime,
	}
}

// persistDID marshals value and saves it in store for given key
func persistDID(store storage.Store, key string, value *did.Doc) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal : %w", err)
	}
	err = store.Put(key, bytes)
	if err != nil {
		return fmt.Errorf("failed to save in store: %w", err)
	}
	return nil
}

func getDID(store storage.Store, key string) (*did.Doc, error) {
	bytes, err := store.Get(key)
	if err != nil {
		return nil, err
	}

	didDoc := did.Doc{}
	if err := json.Unmarshal(bytes, &didDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal did document: %w", err)
	}

	return &didDoc, nil
}
