/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore/exampleformatters"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

type mockFormatter struct {
	errFormat error
}

func (m *mockFormatter) Format(string, []byte, ...spi.Tag) (string, []byte, []spi.Tag, error) {
	return "", nil, nil, m.errFormat
}

func (m *mockFormatter) Deformat(string, []byte, ...spi.Tag) (string, []byte, []spi.Tag, error) {
	return "", nil, nil, errors.New("key, value or tags deformatting failure")
}

func TestCommon(t *testing.T) {
	t.Run("With no-op formatter", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		storagetest.TestAll(t, provider)
	})
	t.Run("With base64 formatter", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.Base64Formatter{})
		require.NotNil(t, provider)

		storagetest.TestAll(t, provider)
	})
}

func TestFormattedProvider_OpenStore(t *testing.T) {
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{
			ErrOpenStore: errors.New("open store failure"),
		},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in underlying provider: open store failure")
		require.Nil(t, store)
	})
}

func TestFormattedProvider_SetStoreConfig(t *testing.T) {
	t.Run("Fail to format tag names", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("tags formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig("StoreName", spi.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, "failed to format tag names: tags formatting failure")
	})
	t.Run("Fail to store config in store config store", func(t *testing.T) {
		provider := formattedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrPut: errors.New("put failure")}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig("StoreName", spi.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, "failed to store config in store config store: "+
			"failed to put formatted data in underlying store: put failure")
	})
}

func TestFormattedProvider_GetStoreConfig(t *testing.T) {
	t.Run("Fail to get store config from store config store", func(t *testing.T) {
		provider := formattedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrGet: errors.New("get failure")}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		_, err := provider.OpenStore("StoreName")
		require.NoError(t, err)

		config, err := provider.GetStoreConfig("StoreName")
		require.EqualError(t, err, "failed to get store config from the store config store: "+
			"failed to get formatted value from underlying store: get failure")
		require.Empty(t, config)
	})
	t.Run("Fail to unmarshal config bytes", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		_, err := provider.OpenStore("StoreName")
		require.NoError(t, err)

		config, err := provider.GetStoreConfig("StoreName")
		require.EqualError(t, err, "failed to unmarshal tags bytes into a tag slice: "+
			"unexpected end of JSON input")
		require.Empty(t, config)
	})
}

func TestFormattedProvider_Close(t *testing.T) {
	t.Run("Fail to close underlying provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{ErrClose: errors.New("close failure")},
			&mockFormatter{})
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close underlying provider: close failure")
	})
}

func TestFormatStore_Put(t *testing.T) {
	t.Run("Fail to format", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("KeyName", []byte("value"), spi.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, "failed to format data: formatting failure")
	})
}

func TestFormatStore_Get(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
		require.Nil(t, value)
	})
	t.Run("Fail to deformat", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{GetReturn: []byte("value")}},
			&mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("KeyName")
		require.EqualError(t, err, `failed to deformat value "value" returned from the underlying store: `+
			`key, value or tags deformatting failure`)
		require.Nil(t, value)
	})
}

func TestFormatStore_GetTags(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.GetTags("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
		require.Nil(t, value)
	})
	t.Run("Fail to deformat tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
			&mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.GetTags("KeyName")
		require.EqualError(t, err, "failed to deformat tags: key, value or tags deformatting failure")
		require.Nil(t, value)
	})
}

func TestFormatStore_GetBulk(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.GetBulk("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
		require.Nil(t, value)
	})
}

func TestFormatStore_Query(t *testing.T) {
	t.Run("Fail to format tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("tags formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		t.Run("Tag name only query", func(t *testing.T) {
			iterator, err := store.Query("TagName1")
			require.EqualError(t, err, `failed to format tag name "TagName1": tags formatting failure`)
			require.Empty(t, iterator)
		})
		t.Run("Tag name and value query", func(t *testing.T) {
			iterator, err := store.Query("TagName1:TagValue1")
			require.EqualError(t, err, `failed to format tag: tags formatting failure`)
			require.Empty(t, iterator)
		})
	})
	t.Run("Fail to query underlying store", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{
			OpenStoreReturn: &mock.Store{
				ErrQuery: errors.New("query failure"),
			},
		},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		t.Run("Tag name only query", func(t *testing.T) {
			iterator, err := store.Query("TagName1")
			require.EqualError(t, err, `failed to query underlying store: query failure`)
			require.Empty(t, iterator)
		})
		t.Run("Tag name and value query", func(t *testing.T) {
			iterator, err := store.Query("TagName1:TagValue1")
			require.EqualError(t, err, `failed to query underlying store: query failure`)
			require.Empty(t, iterator)
		})
	})
}

func TestFormatStore_Delete(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
	})
}

func TestFormatStore_Batch(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormat: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Batch([]spi.Operation{
			{
				Key:   "KeyName",
				Value: []byte("Value1"),
			},
		})
		require.EqualError(t, err, "failed to format data: key formatting failure")
	})
	t.Run("Fail to perform formatted operations in underlying store", func(t *testing.T) {
		provider := formattedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrBatch: errors.New("batch failure")}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Batch([]spi.Operation{
			{
				Key:   "KeyName1",
				Value: []byte("Value1"),
			},
		})
		require.EqualError(t, err, "failed to perform formatted operations in underlying store: batch failure")
	})
}

func TestFormatStore_Close(t *testing.T) {
	t.Run("Fail to close underlying store", func(t *testing.T) {
		provider := formattedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrClose: errors.New("close failure")}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.EqualError(t, err, "failed to close underlying store: close failure")
	})
}

func TestFormattedIterator(t *testing.T) {
	provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{QueryReturn: &mock.Iterator{
		ErrNext:  errors.New("next failure"),
		ErrKey:   errors.New("key failure"),
		ErrValue: errors.New("value failure"),
		ErrTags:  errors.New("tags failure"),
		ErrClose: errors.New("close failure"),
	}}},
		&exampleformatters.NoOpFormatter{})
	require.NotNil(t, provider)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)
	require.NotNil(t, store)

	iterator, err := store.Query("TagName1")
	require.NoError(t, err)
	require.NotNil(t, iterator)

	t.Run("Next: fail to move entry pointer in the underlying iterator", func(t *testing.T) {
		ok, err := iterator.Next()
		require.EqualError(t, err, "failed to move the entry pointer in the underlying iterator: next failure")
		require.False(t, ok)
	})
	t.Run("Key: fail to get formatted key from the underlying iterator", func(t *testing.T) {
		key, err := iterator.Key()
		require.EqualError(t, err, "failed to get formatted key from the underlying iterator: key failure")
		require.Empty(t, key)
	})
	t.Run("Value: fail to get formatted value from the underlying iterator", func(t *testing.T) {
		value, err := iterator.Value()
		require.EqualError(t, err, "failed to get formatted value from the underlying iterator: value failure")
		require.Nil(t, value)
	})
	t.Run("Tags: fail to get formatted tags from the underlying iterator", func(t *testing.T) {
		tags, err := iterator.Tags()
		require.EqualError(t, err, "failed to get formatted tags from the underlying iterator: tags failure")
		require.Nil(t, tags)
	})
	t.Run("Close: fail to close underlying iterator", func(t *testing.T) {
		err := iterator.Close()
		require.EqualError(t, err, "failed to close underlying iterator: close failure")
	})
}
