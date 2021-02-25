/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// package prefix offers provider.Store wrappers for stores with certain constraints on ID values such as
// reserved prefix character values (eg IDs starting with underscore) by prefixing it with IDPrefix.

package prefix

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// StorageKIDPrefix is the KID prefix for key IDs (used by localkms).
const StorageKIDPrefix = "k"

// NewPrefixStoreWrapper creates a new StorePrefixWrapper of store.
func NewPrefixStoreWrapper(store storage.Store, prefix string) (*StorePrefixWrapper, error) {
	if prefix == "" {
		return nil, errors.New("newPrefixStoreWrapper: prefix is empty")
	}

	return &StorePrefixWrapper{store: store, prefix: prefix}, nil
}

// StorePrefixWrapper is a wrapper store that prepends IDPrefix to IDs.
// IDs will be stored in the embedded store with IDPrefix as prefix while the user of this wrapper store will interact
// the original unchanged ID.
type StorePrefixWrapper struct {
	store  storage.Store
	prefix string
}

// Put stores v with k ID by prefixing it with IDPrefix.
func (b *StorePrefixWrapper) Put(k string, v []byte, tags ...storage.Tag) error {
	if k != "" {
		k = b.prefix + k
	}

	return b.store.Put(k, v)
}

// Get fetches the record based on k by first prefixing it with IDPrefix.
func (b *StorePrefixWrapper) Get(k string) ([]byte, error) {
	if k != "" {
		k = b.prefix + k
	}

	return b.store.Get(k)
}

// GetTags is not implemented.
func (b *StorePrefixWrapper) GetTags(string) ([]storage.Tag, error) {
	panic("implement me")
}

// GetBulk is not implemented.
func (b *StorePrefixWrapper) GetBulk(...string) ([][]byte, error) {
	panic("implement me")
}

// Query is not implemented.
func (b *StorePrefixWrapper) Query(string, ...storage.QueryOption) (storage.Iterator, error) {
	panic("implement me")
}

// Delete will delete a record with k by prefixing it with IDPrefix first.
func (b *StorePrefixWrapper) Delete(k string) error {
	if k != "" {
		k = b.prefix + k
	}

	return b.store.Delete(k)
}

// Batch is not implemented.
func (b *StorePrefixWrapper) Batch(operations []storage.Operation) error {
	panic("implement me")
}

// Flush is not implemented.
func (b *StorePrefixWrapper) Flush() error {
	panic("implement me")
}

// Close is not implemented.
func (b *StorePrefixWrapper) Close() error {
	panic("implement me")
}
