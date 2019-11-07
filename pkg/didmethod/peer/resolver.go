/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
)

// DIDResolver resolver
type DIDResolver struct {
	store *DIDStore
}

// NewDIDResolver new Peer DID resolver instance
func NewDIDResolver(store *DIDStore) *DIDResolver {
	return &DIDResolver{store: store}
}

// Read implements didresolver.DidMethod.Read interface (https://w3c-ccg.github.io/did-resolution/#resolving-input)
func (resl *DIDResolver) Read(didID string, _ ...didresolver.ResolveOpt) (*did.Doc, error) {
	// get the document from the store
	doc, err := resl.store.Get(didID)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	if doc == nil {
		return nil, didresolver.ErrNotFound
	}

	return doc, nil
}

// Accept did method
func (resl *DIDResolver) Accept(method string) bool {
	return method == didMethod
}
