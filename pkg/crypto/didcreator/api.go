/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcreator

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto/internal/didopts"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// DIDCreator provides features to create and query DID document
type DIDCreator interface {
	// CreateDID Creates a new DID document.
	//
	// Args:
	//
	// method: DID method
	//
	// opts: options to create DID
	//
	// Returns:
	//
	// did: DID document
	//
	// error: error
	CreateDID(method string, opts ...DocOpts) (*did.Doc, error)

	// GetDID Gets an already-created DID document by ID.
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

// DocOpts is a create DID option
type DocOpts func(opts *didopts.CreateDIDOpts)

// WithServiceType service type of DID document to be created
func WithServiceType(serviceType string) DocOpts {
	return func(opts *didopts.CreateDIDOpts) {
		opts.ServiceType = serviceType
	}
}
