/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package base58wrapper

import (
	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// package base58wrapper offers provider.Store wrappers for stores with certain constraints on key values such as
// reserved prefix values (eg key IDs starting with underscore) by wrapping key values in another format supported by
// the store.

// NewBase58StoreWrapper creates a new Base58StoreWrapper of store.
func NewBase58StoreWrapper(store storage.Store) storage.Store {
	return &Base58StoreWrapper{store: store}
}

// Base58StoreWrapper is a wrapper store that converts key IDs from base64 to base58 encoded values.
// Keys IDs will be stored in the embedded store base58 encoded while the user of this wrapper store will interact with
// the wrapper store using key IDs base64 raw (no padding) URL encoded.
type Base58StoreWrapper struct {
	store storage.Store
}

func convert(k string) string {
	b58k := base58.Encode([]byte(k))

	return b58k
}

// Put stores the key and the record by converting the key from base64 to base58 encoded value first.
func (b *Base58StoreWrapper) Put(k string, v []byte) error {
	b58k := convert(k)

	return b.store.Put(b58k, v)
}

// Get fetches the record based on key by converting the key ID from base58 to base64 encoded value first.
func (b *Base58StoreWrapper) Get(k string) ([]byte, error) {
	b58k := convert(k)

	return b.store.Get(b58k)
}

// Iterator returns an iterator for the latest snapshot of the underlying store.
//
// Args:
//
// startKey: Start of the key range, include in the range by converting it from base64 to base58 encoded value first.
// endKey: End of the key range, not include in the range by converting it from base64 to base58 encoded value first.
//
// Returns:
//
// StoreIterator: a wrapped iterator for result range.
func (b *Base58StoreWrapper) Iterator(startKey, endKey string) storage.StoreIterator {
	// base58 encoding doesn't maintain the same prefix for values using the same prefix,
	// eg `abc_123` encoded is "4h3c6pUcw4" and `abc_` encoded "3VNr6J" which is not the prefix of `abc_123` base58
	// encoded.  This means StoreIterator cannot iterate through base58 encoded keys.
	// For this reason, this wrapper doesn't support the iterator.
	return nil
}

// Delete will delete a record with k by converting it from base64 to base58 encoded value first.
func (b *Base58StoreWrapper) Delete(k string) error {
	b58k := convert(k)

	return b.store.Delete(b58k)
}
