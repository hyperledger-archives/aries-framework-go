/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

// MockDIDCreator mock implementation of DID creator
// to be used only for unit tests
type MockDIDCreator struct {
	Failure error
	Doc     *did.Doc
}

// CreateDID mock implementation of create DID
func (m *MockDIDCreator) CreateDID(opts ...wallet.DocOpts) (*did.Doc, error) {
	if m.Failure != nil {
		return nil, m.Failure
	}

	doc := m.Doc
	if doc == nil {
		doc = createDefaultDID()
	}

	return doc, nil
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
