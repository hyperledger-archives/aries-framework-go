/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"github.com/google/tink/go/keyset"

	mockkms "github.com/hyperledger/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// KeyManager mocks a local Key Management Service + ExportableKeyManager.
type KeyManager = mockkms.KeyManager

// CreateMockAESGCMKeyHandle is a utility function that returns a mock key (for tests only, not registered in Tink).
func CreateMockAESGCMKeyHandle() (*keyset.Handle, error) {
	return mockkms.CreateMockAESGCMKeyHandle()
}

// CreateMockED25519KeyHandle is a utility function that returns a mock key (for tests only, not registered in Tink).
func CreateMockED25519KeyHandle() (*keyset.Handle, error) {
	return mockkms.CreateMockED25519KeyHandle()
}

// Provider provides mock Provider implementation.
type Provider = mockkms.Provider

// NewProviderForKMS creates a new mock Provider to create a KMS.
func NewProviderForKMS(storeProvider storage.Provider, secretLock secretlock.Service) (*Provider, error) {
	return mockkms.NewProviderForKMS(storeProvider, secretLock)
}
