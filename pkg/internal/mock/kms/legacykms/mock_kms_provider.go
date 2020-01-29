/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacykms

import (
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// NewMockProvider will create a new mock LegacyKMS Provider that builds a LegacyKMS with the keypairs list kp
func NewMockProvider(kp ...*cryptoutil.MessagingKeys) (*mockprovider.Provider, error) {
	store := make(map[string][]byte)

	for _, k := range kp {
		marshalledKP, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}

		store[base58.Encode(k.EncKeyPair.Pub)] = marshalledKP
		// mocking behaviour in BaseKMS.ConvertToEncryptionKey() where it stores
		// MessagingKeys twice (1 for enc and 1 for sig)
		store[base58.Encode(k.SigKeyPair.Pub)] = marshalledKP
	}

	mProvider := &mockProvider{&mockstorage.MockStoreProvider{
		Store: &mockstorage.MockStore{
			Store: store,
		}}}

	w, err := legacykms.New(mProvider)
	if err != nil {
		return nil, err
	}

	mockKMSProvider := &mockprovider.Provider{
		KMSValue: w,
	}

	return mockKMSProvider, nil
}

// mockProvider mocks provider for LegacyKMS
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

// StorageProvider() returns the mock storage provider of this mock LegacyKMS provider
func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}
