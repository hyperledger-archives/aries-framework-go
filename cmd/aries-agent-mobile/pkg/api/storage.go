/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The interfaces here are similar to the ones in aries-framework-go/spi/storage. However, those interfaces use types
// that aren't supported by mobile bindings.
// See https://pkg.go.dev/golang.org/x/mobile/cmd/gobind#hdr-Type_restrictions.
// The interfaces here use supported types only, and the wrapper in
// aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/storage is used to convert between the
// mobile-bindings-compatible and spi/storage Go interfaces.

package api

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a store with the given name and returns a handle.
	// If the store has never been opened before, then it is created.
	// Store names are not case-sensitive. If name is blank, then an error will be returned.
	OpenStore(name string) (Store, error)

	// SetStoreConfig sets the configuration on a store.
	// The "config" argument must be JSON representing a of aries-framework-go/spi/storage/StoreConfiguration.
	// The store must be created prior to calling this method.
	// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
	// If name is blank, then an error will be returned.
	SetStoreConfig(name string, config []byte) error

	// GetStoreConfig gets the current store configuration.
	// The store must be created prior to calling this method.
	// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
	// If name is blank, then an error will be returned.
	// The returned array of bytes is expected to be JSON that can be unmarshalled to a
	// aries-framework-go/spi/storage/StoreConfiguration.
	GetStoreConfig(name string) ([]byte, error)

	// Close closes all stores created under this store provider.
	// For persistent store implementations, this does not delete any data in the stores.
	Close() error
}

// Store represents a storage database.
type Store interface {
	// Put stores the key + value pair along with the (optional) tags.
	// The "tags" argument is optional, but if present,
	// must be JSON representing an array of aries-framework-go/spi/storage/Tag.
	// If key is empty or value is nil, then an error will be returned.
	Put(key string, value, tags []byte) error

	// Get fetches the value associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	Get(key string) ([]byte, error)

	// Get fetches all tags associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	// The returned array of bytes is expected to be JSON that can be unmarshalled to an array of
	// aries-framework-go/spi/storage/Tag.
	GetTags(key string) ([]byte, error)

	// GetBulk fetches the values associated with the given keys.
	// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
	// Depending on the implementation, this method may be faster than calling Get for each key individually.
	// The "keys" argument must be JSON representing an array of strings, one for each key.
	// If any of the given keys are empty, then an error will be returned.
	// The returned array of bytes is expected to be a JSON representation of the values, one for each key, that can
	// be unmarshalled to a [][]byte.
	GetBulk(keys []byte) ([]byte, error)

	// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
	// If TagValue is not provided, then all data associated with the TagName will be returned.
	// For now, expression can only be a single tag Name + Value pair.
	// PageSize sets the maximum page size for data retrievals done within the Iterator returned by the Query call.
	// Paging is handled internally by the Iterator. Higher values may reduce CPU time and the number of database calls at
	// the expense of higher memory usage.
	Query(expression string, pageSize int) (Iterator, error)

	// Delete deletes the key + value pair (and all tags) associated with key.
	// If key is empty, then an error will be returned.
	Delete(key string) error

	// Batch performs multiple Put and/or Delete operations in order.
	// Depending on the implementation, this method may be faster than repeated Put and/or Delete calls.
	// The "operations" argument must be JSON representing an array of aries-framework-go/spi/storage/Operation.
	// If any of the given keys are empty, then an error will be returned.
	Batch(operations []byte) error

	// Flush forces any queued up Put and/or Delete operations to execute.
	// If the Store implementation doesn't queue up operations, then this method is a no-op.
	Flush() error

	// Close closes this store object, freeing resources. For persistent store implementations, this does not delete
	// any data in the underlying databases.
	Close() error
}

// Iterator allows for iteration over a collection of entries in a store.
type Iterator interface {
	// Next moves the pointer to the next entry in the iterator. It returns false if the iterator is exhausted.
	Next() (bool, error)

	// Key returns the key of the current entry.
	Key() (string, error)

	// Value returns the value of the current entry.
	Value() ([]byte, error)

	// Tags returns the tags associated with the key of the current entry.
	// The returned array of bytes is expected to be JSON that can be unmarshalled to an array of
	// aries-framework-go/spi/storage/Tag.
	Tags() ([]byte, error)

	// Close closes this iterator object, freeing resources.
	Close() error
}
