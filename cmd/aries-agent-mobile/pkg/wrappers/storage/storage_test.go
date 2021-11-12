/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	. "github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/storage"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

// spiProviderWrapper represents an implementation of the mobile binding storage interface that wraps a spi.Provider.
// This can be thought of as the inverse of Provider in the storage.go file associated with this test file.
// Since we don't have any real mobile binding storage implementations here, the spiProviderWrapper
// allows us to unit-test the logic in storage.go by leveraging any existing spi/storage implementation.
type spiProviderWrapper struct{ spi.Provider }

func (s *spiProviderWrapper) OpenStore(name string) (api.Store, error) {
	spiStore, err := s.Provider.OpenStore(name)

	return &spiStoreWrapper{Store: spiStore}, err
}

func (s *spiProviderWrapper) SetStoreConfig(name string, storeConfigBytes []byte) error {
	var storeConfig spi.StoreConfiguration

	err := json.Unmarshal(storeConfigBytes, &storeConfig)
	if err != nil {
		return err
	}

	return s.Provider.SetStoreConfig(name, storeConfig)
}

func (s *spiProviderWrapper) GetStoreConfig(name string) ([]byte, error) {
	storeConfig, err := s.Provider.GetStoreConfig(name)
	if err != nil {
		return nil, err
	}

	return json.Marshal(storeConfig)
}

type spiStoreWrapper struct{ spi.Store }

func (s *spiStoreWrapper) Put(key string, value, tagsBytes []byte) error {
	var tags []spi.Tag

	if tagsBytes != nil {
		err := json.Unmarshal(tagsBytes, &tags)
		if err != nil {
			return err
		}
	}

	return s.Store.Put(key, value, tags...)
}

func (s *spiStoreWrapper) GetTags(key string) ([]byte, error) {
	tags, err := s.Store.GetTags(key)
	if err != nil {
		return nil, err
	}

	return json.Marshal(tags)
}

func (s *spiStoreWrapper) GetBulk(keysBytes []byte) ([]byte, error) {
	var keys []string

	err := json.Unmarshal(keysBytes, &keys)
	if err != nil {
		return nil, err
	}

	values, err := s.Store.GetBulk(keys...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(values)
}

func (s *spiStoreWrapper) Query(expression string, pageSize int) (api.Iterator, error) {
	iterator, err := s.Store.Query(expression, spi.WithPageSize(pageSize))

	return &spiIteratorWrapper{Iterator: iterator}, err
}

func (s *spiStoreWrapper) Batch(operationsBytes []byte) error {
	var operations []spi.Operation

	err := json.Unmarshal(operationsBytes, &operations)
	if err != nil {
		return err
	}

	return s.Store.Batch(operations)
}

type spiIteratorWrapper struct{ spi.Iterator }

func (s *spiIteratorWrapper) Tags() ([]byte, error) {
	tags, err := s.Iterator.Tags()
	if err != nil {
		return nil, err
	}

	return json.Marshal(tags)
}

func TestCommon(t *testing.T) {
	provider := New(&spiProviderWrapper{mem.NewProvider()})

	storagetest.TestProviderGetOpenStores(t, provider)
	storagetest.TestProviderOpenStoreSetGetConfig(t, provider)
	storagetest.TestPutGet(t, provider)
	storagetest.TestStoreGetTags(t, provider)
	storagetest.TestStoreGetBulk(t, provider)
	storagetest.TestStoreDelete(t, provider)
	storagetest.TestStoreBatch(t, provider)
	storagetest.TestStoreFlush(t, provider)
	storagetest.TestStoreClose(t, provider)
	storagetest.TestProviderClose(t, provider)
}
