/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package storage

import (
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// MockStoreProvider mock store provider.
type MockStoreProvider = mockstore.MockStoreProvider

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *MockStoreProvider {
	return mockstore.NewMockStoreProvider()
}

// NewCustomMockStoreProvider new mock store provider instance
// from existing mock store.
func NewCustomMockStoreProvider(customStore storage.Store) *MockStoreProvider {
	return mockstore.NewCustomMockStoreProvider(customStore)
}

// DBEntry is a value plus optional tags that are associated with some key.
type DBEntry = mockstore.DBEntry

// MockStore mock store.
type MockStore = mockstore.MockStore
