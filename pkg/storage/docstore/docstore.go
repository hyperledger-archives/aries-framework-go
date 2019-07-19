/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docstore

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Provider storage provider interface
type Provider interface {
	// GetStoreHandle returns a handle to the document store
	GetStoreHandle() (Store, error)

	// Close closes the document store provider
	Close() error
}

// Store is the storage interface for DID Documents
type Store interface {
	// Put stores the DID Doc
	Put(*did.Doc) error

	// GetAll fetches the DID Doc based on DID
	Get(string) (*did.Doc, error)
}
