/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connstore

// Connection is a pairwise relation between two DIDs (ours and theirs)
type Connection struct {
	MyDID          string
	TheirDID       string
	TheirPublicKey []byte
	Label          string
}

// Provider storage provider interface
type Provider interface {
	// GetStoreHandle returns a handle to the connection store
	GetStoreHandle(name string) (Store, error)

	// Close closes the connection store provider
	Close()
}

// ConnIterator connection iterator
type ConnIterator interface {
	// Next fetches the next connection record
	Next() (*Connection, bool)
}

// Store is the storage interface for Connections
type Store interface {
	// Put stores the connection
	Put(conn *Connection) error

	// Iter fetches all the stored connections
	Iter() ConnIterator

	// LookupByTheirPublicKey fetches connection details based on their public key
	LookupByTheirPublicKey(pubKey []byte) (*Connection, bool)
}
