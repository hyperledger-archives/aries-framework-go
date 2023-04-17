/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// AriesWrapperStoreName is the store name used when creating a KMS store using kms.NewAriesProviderWrapper.
const AriesWrapperStoreName = "kmsdb"

type ariesProviderKMSStoreWrapper struct {
	store storage.Store
}

func (a *ariesProviderKMSStoreWrapper) Put(keysetID string, key []byte) error {
	return a.store.Put(keysetID, key)
}

func (a *ariesProviderKMSStoreWrapper) Get(keysetID string) ([]byte, error) {
	key, err := a.store.Get(keysetID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("%w. Underlying error: %s",
				ErrKeyNotFound, err.Error())
		}

		return nil, err
	}

	return key, nil
}

func (a *ariesProviderKMSStoreWrapper) Delete(keysetID string) error {
	return a.store.Delete(keysetID)
}

// NewAriesProviderWrapper returns an implementation of the kms.Store interface that wraps an
// Aries provider implementation, allowing it to be used with a KMS.
func NewAriesProviderWrapper(provider storage.Provider) (kms.Store, error) {
	store, err := provider.OpenStore(AriesWrapperStoreName)
	if err != nil {
		return nil, err
	}

	storeWrapper := ariesProviderKMSStoreWrapper{store: store}

	return &storeWrapper, nil
}
