/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// NewMockProvider will create a new mock KMS Provider that builds a KMS with the keypairs list kp
func NewMockProvider(ks ...*cryptoutil.KeySet) (*mockprovider.Provider, error) {
	store := make(map[string][]byte)

	for _, keySet := range ks {
		keySetFromEncPubKeyID := ""

		for _, key := range keySet.Keys {
			marshalledK, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}

			store[key.ID] = marshalledK
			// determine if key is a  public Encryption Key
			kID, err := base64.RawURLEncoding.DecodeString(key.ID)
			if err != nil {
				return nil, err
			}

			if kID[32] == 'e' && kID[33] == 'p' {
				h := sha256.Sum256([]byte(key.Value))
				keySetFromEncPubKeyID = base64.RawURLEncoding.EncodeToString(h[:])
			}
		}
		// for mocking purposes, both KeySet and Key are stored in the same storage
		// real keystore has Key in keystore and KeySet (with Key IDs only) in metadatastore
		// TODO strip down keySet.Keys list from full Key field values and only keep Key.ID to
		// 		to mimic a real metadatastore records. This can be deferred since we're mocking store provider here.
		marshalledKP, err := json.Marshal(keySet)
		if err != nil {
			return nil, err
		}

		store[keySet.ID] = marshalledKP // store with hashed sigPubKey ID (pre-built in keySet.ID)

		// TODO remove private keys from keyset stored with keySetFromEncPubKeyID to mimic the default KMS
		// 		implementation. It is stored with pubSigKey and pubEncKey only.
		//		This can be deferred since we're mocking store provider here. Tests must ensure to not use private keys
		//		from this entry as they do not exist in the real KMS implementation in metadatastore.
		store[keySetFromEncPubKeyID] = marshalledKP // store with hashed encPubKey ID for decryption (pre-built above)
	}

	mProvider := &mockProvider{&mockstorage.MockStoreProvider{
		Store: &mockstorage.MockStore{
			Store: store,
		}}}

	w, err := kms.New(mProvider)
	if err != nil {
		return nil, err
	}

	mockKMSProvider := &mockprovider.Provider{
		KMSValue: w,
	}

	return mockKMSProvider, nil
}

// mockProvider mocks provider for KMS
type mockProvider struct {
	storage *mockstorage.MockStoreProvider
}

// StorageProvider() returns the mock storage provider of this mock KMS provider
func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

// InboundTransportEndpoint returns a mock inbound endpoint
func (m *mockProvider) InboundTransportEndpoint() string {
	return "sample-endpoint.com"
}
