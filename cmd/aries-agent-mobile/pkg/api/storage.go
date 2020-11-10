/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// StoreIterator is the iterator for the latest snapshot of the underlying store.
type StoreIterator interface {
	// Next moves the iterator to the next key/value pair.
	// It returns false if the iterator is exhausted.
	Next() bool

	// Free releases associated resources. Release should always success
	// and can be called multiple times without causing error.
	Free()

	// Error returns any accumulated error. Exhausting all the key/value pairs
	// is not considered to be an error.
	Error() error

	// Key returns the key of the current key/value pair, or nil if done.
	// The caller should not modify the contents of the returned slice, and
	// its contents may change on the next call to any 'seeks method'.
	Key() []byte

	// Value returns the value of the current key/value pair, or nil if done.
	// The caller should not modify the contents of the returned slice, and
	// its contents may change on the next call to any 'seeks method'.
	Value() []byte
}

// Store is the storage interface.
type Store interface {
	// Put stores the key and the record
	Put(k string, v []byte) error

	// Get fetches the record based on key
	Get(k string) ([]byte, error)

	// Iterator returns an iterator for the latest snapshot of the
	// underlying store
	//
	// Args:
	//
	// startKey: Start of the key range, include in the range.
	// endKey: End of the key range, not include in the range.
	//
	// Returns:
	//
	// StoreIterator: iterator for result range
	Iterator(startKey, endKey string) StoreIterator

	// Delete will delete a record with k key
	Delete(k string) error
}

// StorageProvider defines storage interface.
type StorageProvider interface {
	// OpenStore opens a store with given name space and returns the handle
	OpenStore(name string) (Store, error)

	// CloseStore closes store of given name space
	CloseStore(name string) error

	// Close closes all stores created under this store provider
	Close() error
}
