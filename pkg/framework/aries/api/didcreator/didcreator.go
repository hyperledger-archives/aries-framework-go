/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcreator

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Creator allows for creation of DID document
type Creator interface {
	// Creates new DID document.
	//
	// Args:
	//
	// method: did method
	// opts: options to create DID
	//
	// Returns:
	//
	// did: DID document
	//
	// error: error
	Create(method string, opts ...DocOpts) (*did.Doc, error)
}

// CreateDIDOpts holds the options for creating DID
type CreateDIDOpts struct {
	ServiceType     string
	KeyType         string
	ServiceEndpoint string
}

// DocOpts is a create DID option
type DocOpts func(opts *CreateDIDOpts)

// WithServiceType service type of DID document to be created
func WithServiceType(serviceType string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.ServiceType = serviceType
	}
}

// WithKeyType allows for setting key type
func WithKeyType(keyType string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.KeyType = keyType
	}
}

// WithServiceEndpoint allows for setting service endpoint
func WithServiceEndpoint(serviceEndpoint string) DocOpts {
	return func(opts *CreateDIDOpts) {
		opts.ServiceEndpoint = serviceEndpoint
	}
}

// PubKey contains public key type and value
type PubKey struct {
	Value string // base58 encoded
	Type  string
}

// DidMethod defines method interface for creation of did documents
type DidMethod interface {
	// Build builds did document with specified public key and options
	Build(pubKey *PubKey, opts *CreateDIDOpts) (*did.Doc, error)
	// Accept registers this DID method document builder with the given method.
	Accept(method string) bool
}
