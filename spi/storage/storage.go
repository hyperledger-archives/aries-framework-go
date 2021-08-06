/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	"errors"
	"fmt"
	standardlog "log"

	spi "github.com/hyperledger/aries-framework-go/spi/log"
)

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
	// TagNames is a list of Tag names that key + value pairs in this store can be associated with.
	// Tag names cannot contain any ':' characters.
	TagNames []string `json:"tagNames,omitempty"`
}

// SortOrder specifies the sort order of query results.
type SortOrder int

const (
	// SortAscending indicates that the query results must be sorted in ascending order.
	SortAscending SortOrder = iota
	// SortDescending indicates that the query results must be sorted in descending order.
	SortDescending
)

// SortOptions sets the order that results from an Iterator will be returned in. Sorting is based on the tag values
// associated with the TagName chosen below. The TagName you use below can be the same as the one you're querying on,
// or it can be a different one. However, you must ensure that the TagName set below is in the
// Store's StoreConfiguration before trying to use it for sorting, or unexpected behaviour may occur.
// If tag value strings are decimal numbers, then the sorting will be based on their numerical value instead of
// the string representations of those numbers (i.e. numerical sorting, not lexicographic).
// TagName cannot be blank.
type SortOptions struct {
	Order   SortOrder
	TagName string
}

// QueryOptions represents various options for Query calls in a store.
type QueryOptions struct {
	// PageSize sets the page size used by the Store.Query method.
	PageSize int
	// InitialPageNum sets the page for the iterator returned from Store.Query to start from.
	// InitialPageNum=0 means start from the first page.
	InitialPageNum int
	// SortOptions defines the sort order.
	SortOptions *SortOptions
}

// QueryOption represents an option for a Store.Query call.
type QueryOption func(opts *QueryOptions)

// WithPageSize sets the maximum page size for data retrievals done within the Iterator returned by the Query call.
// Paging is handled internally by the Iterator. Higher values may reduce CPU time and the number of database calls at
// the expense of higher memory usage.
func WithPageSize(size int) QueryOption {
	return func(opts *QueryOptions) {
		opts.PageSize = size
	}
}

// WithInitialPageNum sets the page number for an Iterator to start from. If this option isn't used,
// then the Iterator will start from the first page.
// Page number counting starts from 0 (i.e. initialPageNum=0 means that the iterator will start from the first page).
func WithInitialPageNum(initialPageNum int) QueryOption {
	return func(opts *QueryOptions) {
		opts.InitialPageNum = initialPageNum
	}
}

// WithSortOrder sets the sort order used by a Store.Query call. See SortOptions for more information.
// If this option isn't used, then the result order from the Iterator will be determined (perhaps arbitrarily) by the
// underlying database implementation.
func WithSortOrder(sortOptions *SortOptions) QueryOption {
	return func(opts *QueryOptions) {
		opts.SortOptions = sortOptions
	}
}

// Tag represents a Name + Value pair that can be associated with a key + value pair for querying later.
type Tag struct {
	// Name can be used to tag a given key + value pair as belonging to a group.
	// Tag Names are static values that the store must be configured with (see TagNames in StoreConfiguration).
	// Tag Names cannot contain any ':' characters.
	Name string `json:"name,omitempty"`
	// Value can be used to indicate some optional metadata associated with a given key + value pair + tag name.
	// Unlike Tag Names, Tag Values are dynamic and are not specified during store creation.
	// Tag Values cannot contain any ':' characters.
	Value string `json:"value,omitempty"`
}

// Operation represents an operation to be performed in the Batch method.
type Operation struct {
	Key   string `json:"key,omitempty"`
	Value []byte `json:"value,omitempty"` // A nil value will result in a delete operation.
	Tags  []Tag  `json:"tags,omitempty"`  // Optional.
}

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a Store with the given name and returns a handle.
	// If the underlying database for the given name has never been created before, then it is created.
	// Store names are not case-sensitive. If name is blank, then an error will be returned.
	OpenStore(name string) (Store, error)

	// SetStoreConfig sets the configuration on a Store. If the underlying database for the given name has never been
	// created by a call to OpenStore at some point, then an error wrapping ErrStoreNotFound will be returned. This
	// method will not open a Store in the Provider.
	// If name is blank, then an error will be returned.
	SetStoreConfig(name string, config StoreConfiguration) error

	// GetStoreConfig gets the current Store configuration.
	// If the underlying database for the given name has never been
	// created by a call to OpenStore at some point, then an error wrapping ErrStoreNotFound will be returned. This
	// method will not open a store in the Provider.
	// If name is blank, then an error will be returned.
	GetStoreConfig(name string) (StoreConfiguration, error)

	// GetOpenStores returns all Stores currently open in the Provider.
	GetOpenStores() []Store

	// Close closes all open Stores in this Provider
	// For persistent Store implementations, this does not delete any data in the underlying databases.
	Close() error
}

// Store represents a storage database.
type Store interface {
	// Put stores the key + value pair along with the (optional) tags.
	// If key is empty or value is nil, then an error will be returned.
	Put(key string, value []byte, tags ...Tag) error

	// Get fetches the value associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	Get(key string) ([]byte, error)

	// GetTags fetches all tags associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	GetTags(key string) ([]Tag, error)

	// GetBulk fetches the values associated with the given keys.
	// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
	// Depending on the implementation, this method may be faster than calling Get for each key individually.
	// If any of the given keys are empty, then an error will be returned.
	GetBulk(keys ...string) ([][]byte, error)

	// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
	// If TagValue is not provided, then all data associated with the TagName will be returned.
	// For now, expression can only be a single tag Name + Value pair.
	// If no options are provided, then defaults will be used.
	Query(expression string, options ...QueryOption) (Iterator, error)

	// Delete deletes the key + value pair (and all tags) associated with key.
	// If key is empty, then an error will be returned.
	Delete(key string) error

	// Batch performs multiple Put and/or Delete operations in order.
	// Depending on the implementation, this method may be faster than repeated Put and/or Delete calls.
	// If any of the given keys are empty, or the operations slice is empty or nil, then an error will be returned.
	Batch(operations []Operation) error

	// Flush forces any queued up Put and/or Delete operations to execute.
	// If the Store implementation doesn't queue up operations, then this method is a no-op.
	Flush() error

	// Close closes this store object, freeing resources. For persistent store implementations, this does not delete
	// any data in the underlying databases.
	// Close can be called repeatedly on the same store multiple times without causing an error.
	Close() error
}

// Iterator allows for iteration over a collection of entries in a store.
type Iterator interface {
	// Next moves the pointer to the next entry in the iterator.
	// It returns false if the iterator is exhausted - this is not considered an error.
	Next() (bool, error)

	// Key returns the key of the current entry.
	Key() (string, error)

	// Value returns the value of the current entry.
	Value() ([]byte, error)

	// Tags returns the tags associated with the key of the current entry.
	Tags() ([]Tag, error)

	// TotalItems returns a count of the number of entries (key + value + tags triplets) matched by the query
	// that generated this Iterator. This count is not affected by the page settings used (i.e. the count is of all
	// results as if you queried starting from the first page and with an unlimited page size).
	TotalItems() (int, error)

	// Close closes this iterator object, freeing resources.
	Close() error
}

// Close closes iterator and logs any error that occurs.
// Is logger is nil, then the standard Go logger will be used.
func Close(iterator Iterator, logger spi.Logger) {
	errClose := iterator.Close()
	if errClose != nil {
		if logger == nil {
			standardlog.Println(fmt.Sprintf("failed to close iterator: %s", errClose.Error()))
		} else {
			logger.Errorf("failed to close iterator: %s", errClose.Error())
		}
	}
}
