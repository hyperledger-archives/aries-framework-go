/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import "errors"

// ErrDataNotFound is returned when data not found
var ErrDataNotFound = errors.New("data not found")

// Provider storage provider interface
type Provider interface {
	// OpenStore opens a store with given name space and returns the handle
	OpenStore(name string) (Store, error)

	// CloseStore closes store of given name space
	CloseStore(name string) error

	// Close closes all stores created under this store provider
	Close() error
}

// Store is the storage interface
type Store interface {
	// Put stores the key and the record
	Put(k string, v []byte) error

	// Get fetches the record based on key
	Get(k string) ([]byte, error)
}
