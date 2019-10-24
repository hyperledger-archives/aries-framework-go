/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const method = "peer"

// Creator is a DID creator interface
type Creator interface {
	// Creates new local DID document.
	//
	//
	// opts: options to create local DID
	//
	// Returns:
	//
	// did: DID document
	//
	// error: error
	CreateDID(opts ...didcreator.DocOpts) (*did.Doc, error)

	// Gets already created DID document by ID.
	//
	// Args:
	//
	// id: DID identifier
	//
	// Returns:
	//
	// did: DID document
	//
	// error: when document is not found or for any other error conditions
	GetDID(id string) (*did.Doc, error)
}

// provider contains dependencies for DID creator and is typically created by using aries.Context()
type provider interface {
	DIDWallet() didcreator.DIDCreator
}

// NewPeerDIDCreator returns new Peer DID creator
func NewPeerDIDCreator(ctx provider) *PeerDIDCreator {
	return &PeerDIDCreator{ctx.DIDWallet(), method}
}

// PeerDIDCreator creates Peer DIDs
type PeerDIDCreator struct {
	didcreator.DIDCreator
	method string
}

// CreateDID creates new Peer DID
func (l *PeerDIDCreator) CreateDID(opts ...didcreator.DocOpts) (*did.Doc, error) {
	return l.DIDCreator.CreateDID(l.method, opts...)
}

// GetDID gets already created DID document by ID.
func (l *PeerDIDCreator) GetDID(id string) (*did.Doc, error) {
	return l.DIDCreator.GetDID(id)
}
