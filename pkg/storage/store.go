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
	// GetStoreHandle returns a handle to the store
	GetStoreHandle() (Store, error)

	// Close closes the store provider
	Close() error
}

// Store is the storage interface
type Store interface {
	// Put stores the key and the record
	Put(k string, v []byte) error

	// Get fetches the record based on key
	Get(k string) ([]byte, error)
}
