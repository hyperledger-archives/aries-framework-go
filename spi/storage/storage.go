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

var (
	// ErrStoreNotFound is returned when a store is not found.
	ErrStoreNotFound = errors.New("store not found")
	// ErrDataNotFound is returned when data is not found.
	ErrDataNotFound = errors.New("data not found")
	// ErrDuplicateKey is returned when a call is made to Store.Batch using the IsNewKey PutOption with a key that
	// already exists in the database.
	ErrDuplicateKey = errors.New("duplicate key")
)

// StoreConfiguration represents the configuration of a store.
// Currently, it's only used for creating indexes in underlying storage databases.
type StoreConfiguration struct {
	// TagNames is a list of Tag names to create indexes on.
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
// or it can be a different one. Depending on the storage implementation, you may need to ensure that the TagName set
// below is in the Store's StoreConfiguration before trying to use it for sorting (or it may be optional,
// but recommended). If tag value strings are decimal numbers, then the sorting must be based on their numerical value
// instead of the string representations of those numbers (i.e. numerical sorting, not lexicographic).
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
// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
func WithSortOrder(sortOptions *SortOptions) QueryOption {
	return func(opts *QueryOptions) {
		opts.SortOptions = sortOptions
	}
}

// Tag represents a Name + Value pair that can be associated with a key + value pair for querying later.
type Tag struct {
	// Name can be used to tag a given key + value pair as belonging to some sort of common
	// group. Example: Identifying a key+value pair as being a Verifiable Credential by storing it
	// with a tag Name called "VC". When used with the optional Value (see below), tag Name + Value can be used to
	// specify metadata for a given key + value pair. Example: Identifying a Verifiable Credential (stored as a
	// key+value pair) as belonging to a user account by using a tag Name called "UserAccount" and a tag Value called
	// "bob@example.com". Tag Names are intended to be static values that the store is configured with in order to build
	// indexes for queries (see TagNames in StoreConfiguration).
	// Tag Names cannot contain any ':' characters.
	Name string `json:"name,omitempty"`
	// Value can optionally be used to indicate some metadata associated with a tag name for a given key + value pair.
	// See Name above for an example of how this can be used.
	// Tag Values are dynamic and are not specified in a StoreConfiguration.
	// Tag Values cannot contain any ':' characters.
	Value string `json:"value,omitempty"`
}

// PutOptions represents options for a Put Operation.
type PutOptions struct {
	// This is an optimization for a Put Operation. Some storage providers may be able to store data faster if they
	// know beforehand that this key does not currently exist in the database. Unexpected behaviour may occur if
	// this is set to true and the key already exists. See the documentation for the specific storage provider to
	// see if and how this option is used.
	IsNewKey bool `json:"isNewKey,omitempty"`
}

// Operation represents an operation to be performed in the Batch method.
type Operation struct {
	Key        string      `json:"key,omitempty"`
	Value      []byte      `json:"value,omitempty"`      // A nil value will result in a delete operation.
	Tags       []Tag       `json:"tags,omitempty"`       // Optional.
	PutOptions *PutOptions `json:"putOptions,omitempty"` // Optional. Only used for Put Operations.
}

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a Store with the given name and returns it.
	// Depending on the store implementation, this may or may not create an underlying database.
	// The store implementation may defer creating the underlying database until SetStoreConfig is called or
	// data is inserted using Store.Put or Store.Batch.
	// Store names are not case-sensitive. If name is blank, then an error will be returned.
	OpenStore(name string) (Store, error)

	// SetStoreConfig sets the configuration on a Store. It's recommended calling this method at some point before
	// calling Store.Query if your store contains a large amount of data. The underlying database will use this to
	// create indexes to make querying via the Store.Query method faster. If you don't need to use Store.Query, then
	// you don't need to call this method. OpenStore must be called first before calling this method. If not, then an
	// error wrapping ErrStoreNotFound will be returned. This method will not open the store automatically.
	// If name is blank, then an error will be returned.
	SetStoreConfig(name string, config StoreConfiguration) error

	// GetStoreConfig gets the current Store configuration.
	// This method operates a bit differently in that it directly checks the underlying storage implementation to see
	// if the underlying database exists for the given name, rather than checking the currently known list of
	// open stores in memory. If no underlying database can be found, then an error wrapping ErrStoreNotFound will be
	// returned. This means that this method can be used to determine whether an underlying database for a Store
	// already exists or not. This method will not create the database automatically.
	// If name is blank, then an error will be returned.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetStoreConfig(name string) (StoreConfiguration, error)

	// GetOpenStores returns all Stores that are currently open in memory from calling OpenStore.
	// It does not check for all databases that have been created before. They have to have been opened in this Provider
	// object's lifetime from a call to OpenStore.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetOpenStores() []Store

	// Close closes all open Stores in this Provider
	// For persistent Store implementations, this does not delete any data in the underlying databases.
	Close() error
}

// Store represents a storage database.
type Store interface {
	// Put stores the key + value pair along with the (optional) tags. If the key already exists in the database,
	// then the value and tags will be overwritten silently.
	// If value is a JSON-formatted object, then an underlying storage implementation may store it in a way that
	// does not preserve the order of the fields. Therefore, you should avoid doing direct byte-for-byte comparisons
	// with data put in and data retrieved, as the marshalled representation may be different - always unmarshal data
	// first before comparing.
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
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetBulk(keys ...string) ([][]byte, error)

	// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
	// If TagValue is not provided, then all data associated with the TagName will be returned, regardless of their
	// tag values.
	// At a minimum, a store implementation must be able to support querying with a single TagName:TagValue pair, but a
	// store implementation may also support querying for multiple TagName:TagValue pairs by separating them with an
	// && to specify an AND operation or a || to specify an OR operation. For example, a query for
	// TagName1:TagValue1&&TagName2:TagValue2 will return only data that has been tagged with both pairs.
	// This method also supports a number of QueryOptions. If none are provided, then defaults will be used.
	// If your store contains a large amount of data, then it's recommended calling Provider.SetStoreConfig at some
	// point before calling this method in order to create indexes which will speed up queries.
	Query(expression string, options ...QueryOption) (Iterator, error)

	// Delete deletes the key + value pair (and all tags) associated with key.
	// If key is empty, then an error will be returned.
	Delete(key string) error

	// Batch performs multiple Put and/or Delete operations in order. The Puts and Deletes here follow the same rules
	// as described in the Put and Delete method documentation. The only exception is if the operation makes use of
	// the PutOptions.IsNewKey optimization, in which case an error wrapping an ErrDuplicateKey may be returned if it's
	// enabled and a key is used that already exists in the database.
	// Depending on the implementation, this method may be faster than repeated Put and/or Delete calls.
	// If any of the given keys are empty, or the operations slice is empty or nil, then an error will be returned.
	Batch(operations []Operation) error

	// Flush forces any queued up Put and/or Delete operations to execute.
	// If the Store implementation doesn't queue up operations, then this method is a no-op.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	Flush() error

	// Close closes this store object, freeing resources. For persistent store implementations, this does not delete
	// any data in the underlying databases.
	// Close can be called repeatedly on the same store multiple times without causing an error.
	Close() error
}

// Iterator allows for iteration over a collection of entries in a store.
type Iterator interface {
	// Next moves the pointer to the next entry in the iterator.
	// Note that it must be called before accessing the first entry.
	// It returns false if the iterator is exhausted - this is not considered an error.
	Next() (bool, error)

	// Key returns the key of the current entry.
	Key() (string, error)

	// Value returns the value of the current entry.
	Value() ([]byte, error)

	// Tags returns the tags associated with the key of the current entry.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	Tags() ([]Tag, error)

	// TotalItems returns a count of the number of entries (key + value + tags triplets) matched by the query
	// that generated this Iterator. This count is not affected by the page settings used (i.e. the count is of all
	// results as if you queried starting from the first page and with an unlimited page size).
	// Depending on the storage implementation, you may need to ensure that the TagName used in the query is in the
	// Store's StoreConfiguration before trying to call this method (or it may be optional, but recommended).
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
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
