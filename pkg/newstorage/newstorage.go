/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package newstorage

import "errors"

// MultiError represents the errors that occurred during a bulk operation.
type MultiError interface {
	error
	Errors() []error // Errors returns the error objects for all operations.
}

// ErrStoreNotFound is returned when a store is not found.
var ErrStoreNotFound = errors.New("store not found")

// ErrDataNotFound is returned when data is not found.
var ErrDataNotFound = errors.New("data not found")

// StoreConfiguration represents the configuration of a store.
type StoreConfiguration struct {
	TagNames []string // A list of Tag names that key + value pairs in this store can be associated with.
}

// QueryOptions represents various options for Query calls in a store.
type QueryOptions struct {
	pageSize int
}

// QueryOption represents an option for a Query call in a store.
type QueryOption func(opts *QueryOptions)

// WithPageSize sets the maximum page size for data retrievals done within the Iterator returned by the Query call.
// Paging is handled internally by the Iterator. Higher values may reduce CPU time and the number of database calls at
// the expense of higher memory usage.
func WithPageSize(size int) QueryOption {
	return func(opts *QueryOptions) {
		opts.pageSize = size
	}
}

// Tag represents a Name + Value pair that can be associated with a key + value pair for querying later.
type Tag struct {
	// Name can be used to tag a given key + value pair as belonging to a group.
	// Tag Names are static values that the store must be configured with (see TagNames in StoreConfiguration).
	Name string
	// Value can be used to indicate some optional metadata associated with a given key + value pair + tag name.
	// Unlike Tag Names, Tag Values are dynamic and are not specified during store creation.
	Value string
}

// Operation represents an operation to be performed in the Batch method.
type Operation struct {
	Key   string
	Value []byte // A nil value will result in a delete operation
	Tags  []Tag  // Optional
}

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a store with the given name and returns a handle.
	// If the store has never been opened before, then it is created.
	OpenStore(name string) (Store, error)

	// SetStoreConfig sets the configuration on a store.
	// The store must be created prior to calling this method.
	SetStoreConfig(name string, config StoreConfiguration) error

	// GetStoreConfig gets the current store configuration.
	// The store must be created prior to calling this method.
	GetStoreConfig(name string) (StoreConfiguration, error)

	// Close closes all stores created under this store provider.
	// This does not delete any data in the stores, and the stores can be reopened again.
	Close() error
}

// Store represents a storage database.
type Store interface {
	// Put stores the key + value pair along with the (optional) tags.
	Put(key string, value []byte, tags ...Tag) error

	// Get fetches the value associated with the given key.
	Get(key string) ([]byte, error)

	// Get fetches all tags associated with the given key.
	GetTags(k string) ([]Tag, error)

	// GetBulk fetches the values associated with the given keys.
	// If a key doesn't exist, then a nil []byte is returned for that value. It is not considered an error.
	// Depending on the implementation, this method may be faster than calling Get for each key individually.
	GetBulk(keys ...string) ([][]byte, error)

	// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
	// If TagValue is not provided, then all data associated with the TagName will be returned.
	// For now, expression can only be a single tag Name + Value pair.
	// If no options are provided, then defaults will be used.
	Query(expression string, options ...QueryOption) (Iterator, error)

	// Delete deletes the key + value pair (and all tags) associated with key.
	Delete(key string) error

	// Batch performs multiple Put and/or Delete operations in order.
	// Depending on the implementation, this method may be faster than repeated Put and/or Delete calls.
	Batch(operations []Operation) error

	// Close closes this store.
	// This does not delete any data in the store, and the store can be reopened again in the future.
	Close() error
}

// Iterator allows for iteration over a collection of key-value pairs.
type Iterator interface {
	// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
	Next() (bool, error)

	// Release releases associated resources.
	Release() error

	// Key returns the key of the current key + value pair.
	Key() (string, error)

	// Value returns the value of the current key + value pair.
	Value() ([]byte, error)

	// Get returns the tags associated with the given key.
	Tags() ([]Tag, error)
}
