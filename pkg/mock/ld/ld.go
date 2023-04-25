/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/component/models/ld/mock"
)

// MockContextStore is a mock JSON-LD context store.
type MockContextStore = mock.ContextStore

// NewMockContextStore returns a new instance of MockContextStore.
func NewMockContextStore() *MockContextStore {
	return mock.NewMockContextStore()
}

// MockRemoteProviderStore is a mock remote JSON-LD context provider store.
type MockRemoteProviderStore = mock.RemoteProviderStore

// NewMockRemoteProviderStore returns a new instance of MockRemoteProviderStore.
func NewMockRemoteProviderStore() *MockRemoteProviderStore {
	return mock.NewMockRemoteProviderStore()
}

// MockService is a mock JSON-LD service.
type MockService = mock.Service
