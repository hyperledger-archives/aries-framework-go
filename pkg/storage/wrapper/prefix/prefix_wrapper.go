/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// package prefix offers provider.Store wrappers for stores with certain constraints on ID values such as
// reserved prefix character values (eg IDs starting with underscore) by prefixing it with IDPrefix.

package prefix

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
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
func (b *StorePrefixWrapper) Put(k string, v []byte) error {
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

// Iterator returns an iterator for the latest snapshot of the underlying store.
//
// Args:
//
// startKey: Start of the key range, include in the range by converting it from base64 to IDPrefix encoded value first.
// endKey: End of the key range, not include in the range by converting it from base64 to IDPrefix encoded value first.
//
// Returns:
//
// StoreIterator: a wrapped iterator for result range.
func (b *StorePrefixWrapper) Iterator(startKey, endKey string) storage.StoreIterator {
	if startKey != "" {
		startKey = b.prefix + startKey
	}

	if endKey != "" {
		endKey = b.prefix + endKey
	}

	return b.store.Iterator(startKey, endKey)
}

// Delete will delete a record with k by prefixing it with IDPrefix first.
func (b *StorePrefixWrapper) Delete(k string) error {
	if k != "" {
		k = b.prefix + k
	}

	return b.store.Delete(k)
}
