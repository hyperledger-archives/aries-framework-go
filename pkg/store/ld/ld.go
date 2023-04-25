/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/component/models/ld/store"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// ContextStoreName is a JSON-LD context store name.
	ContextStoreName = store.ContextStoreName

	// ContextRecordTag is a tag associated with every record in the store.
	ContextRecordTag = store.ContextRecordTag

	// RemoteProviderStoreName is a remote provider store name.
	RemoteProviderStoreName = store.RemoteProviderStoreName

	// RemoteProviderRecordTag is a tag associated with every record in the store.
	RemoteProviderRecordTag = store.RemoteProviderRecordTag
)

// ContextStore represents a repository for JSON-LD context operations.
type ContextStore = store.ContextStore

// ContextStoreImpl is a default implementation of JSON-LD context repository.
type ContextStoreImpl = store.ContextStoreImpl

// NewContextStore returns a new instance of ContextStoreImpl.
func NewContextStore(storageProvider storage.Provider) (*ContextStoreImpl, error) {
	return store.NewContextStore(storageProvider)
}

// RemoteProviderRecord is a record in store with remote provider info.
type RemoteProviderRecord = store.RemoteProviderRecord

// RemoteProviderStore represents a repository for remote context provider operations.
type RemoteProviderStore = store.RemoteProviderStore

// RemoteProviderStoreImpl is a default implementation of remote provider repository.
type RemoteProviderStoreImpl = store.RemoteProviderStoreImpl

// NewRemoteProviderStore returns a new instance of RemoteProviderStoreImpl.
func NewRemoteProviderStore(storageProvider storage.Provider) (*RemoteProviderStoreImpl, error) {
	return store.NewRemoteProviderStore(storageProvider)
}
