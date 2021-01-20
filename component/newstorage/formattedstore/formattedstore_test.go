/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/newstorage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
	newstoragetest "github.com/hyperledger/aries-framework-go/test/newstorage"
)

type mockProvider struct {
	openStoreReturn newstorage.Store
	errOpenStore    error
}

func (m *mockProvider) OpenStore(string) (newstorage.Store, error) {
	return m.openStoreReturn, m.errOpenStore
}

func (m *mockProvider) SetStoreConfig(string, newstorage.StoreConfiguration) error {
	panic("implement me")
}

func (m *mockProvider) GetStoreConfig(string) (newstorage.StoreConfiguration, error) {
	return newstorage.StoreConfiguration{TagNames: []string{"TagName1"}}, nil
}

func (m *mockProvider) Close() error {
	return errors.New("close failure")
}

type mockStore struct {
	errQuery error
}

func (m *mockStore) Put(string, []byte, ...newstorage.Tag) error {
	panic("implement me")
}

func (m *mockStore) Get(string) ([]byte, error) {
	return []byte("value"), nil
}

func (m *mockStore) GetTags(string) ([]newstorage.Tag, error) {
	return nil, nil
}

func (m *mockStore) GetBulk(...string) ([][]byte, error) {
	panic("implement me")
}

func (m *mockStore) Query(string, ...newstorage.QueryOption) (newstorage.Iterator, error) {
	return &mockIterator{}, m.errQuery
}

func (m *mockStore) Delete(string) error {
	panic("implement me")
}

func (m *mockStore) Batch([]newstorage.Operation) error {
	return errors.New("batch failure")
}

func (m *mockStore) Close() error {
	return errors.New("close failure")
}

type mockIterator struct {
}

func (m *mockIterator) Next() (bool, error) {
	return false, errors.New("next failure")
}

func (m *mockIterator) Key() (string, error) {
	return "", errors.New("key failure")
}

func (m *mockIterator) Value() ([]byte, error) {
	return nil, errors.New("value failure")
}

func (m *mockIterator) Tags() ([]newstorage.Tag, error) {
	return nil, errors.New("tags failure")
}

func (m *mockIterator) Close() error {
	return errors.New("close failure")
}

type noOpFormatter struct {
}

func (n *noOpFormatter) FormatKey(key string) (string, error) {
	return key, nil
}

func (n *noOpFormatter) FormatValue(value []byte) ([]byte, error) {
	return value, nil
}

func (n *noOpFormatter) FormatTags(tags ...newstorage.Tag) ([]newstorage.Tag, error) {
	return tags, nil
}

func (n *noOpFormatter) DeformatKey(formattedKey string) (string, error) {
	return formattedKey, nil
}

func (n *noOpFormatter) DeformatValue(formattedValue []byte) ([]byte, error) {
	return formattedValue, nil
}

func (n *noOpFormatter) DeformatTags(formattedTags ...newstorage.Tag) ([]newstorage.Tag, error) {
	return formattedTags, nil
}

type base64Formatter struct {
}

func (b *base64Formatter) FormatKey(key string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(key)), nil
}

func (b *base64Formatter) FormatValue(value []byte) ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(value)), nil
}

func (b *base64Formatter) FormatTags(tags ...newstorage.Tag) ([]newstorage.Tag, error) {
	formattedTags := make([]newstorage.Tag, len(tags))

	for i, tag := range tags {
		formattedTags[i] = newstorage.Tag{
			Name:  base64.StdEncoding.EncodeToString([]byte(tag.Name)),
			Value: base64.StdEncoding.EncodeToString([]byte(tag.Value)),
		}
	}

	return formattedTags, nil
}

func (b *base64Formatter) DeformatKey(formattedKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(formattedKey)
	return string(key), err
}

func (b *base64Formatter) DeformatValue(formattedValue []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(formattedValue))
}

func (b *base64Formatter) DeformatTags(formattedTags ...newstorage.Tag) ([]newstorage.Tag, error) {
	tags := make([]newstorage.Tag, len(formattedTags))

	for i, formattedTag := range formattedTags {
		tagName, err := base64.StdEncoding.DecodeString(formattedTag.Name)
		if err != nil {
			return nil, err
		}

		tagValue, err := base64.StdEncoding.DecodeString(formattedTag.Value)
		if err != nil {
			return nil, err
		}

		tags[i] = newstorage.Tag{
			Name:  string(tagName),
			Value: string(tagValue),
		}
	}

	return tags, nil
}

type mockFormatter struct {
	errFormatKey   error
	errFormatValue error
}

func (m *mockFormatter) FormatKey(key string) (string, error) {
	return key, m.errFormatKey
}

func (m *mockFormatter) FormatValue([]byte) ([]byte, error) {
	return nil, m.errFormatValue
}

func (m *mockFormatter) FormatTags(...newstorage.Tag) ([]newstorage.Tag, error) {
	return nil, errors.New("tags formatting failure")
}

func (m *mockFormatter) DeformatKey(string) (string, error) {
	return "", errors.New("key deformatting failure")
}

func (m *mockFormatter) DeformatValue([]byte) ([]byte, error) {
	return nil, errors.New("value deformatting failure")
}

func (m *mockFormatter) DeformatTags(...newstorage.Tag) ([]newstorage.Tag, error) {
	return nil, errors.New("tags deformatting failure")
}

func TestCommon(t *testing.T) {
	t.Run("With no-op formatter", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &noOpFormatter{})
		require.NotNil(t, provider)

		newstoragetest.TestAll(t, provider)
	})
	t.Run("With base64 formatter", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{})
		require.NotNil(t, provider)

		newstoragetest.TestAll(t, provider)
	})
}

func TestFormattedProvider_OpenStore(t *testing.T) {
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{
			errOpenStore: errors.New("open store failure"),
		},
			&noOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in underlying provider: open store failure")
		require.Nil(t, store)
	})
}

func TestFormattedProvider_SetStoreConfig(t *testing.T) {
	t.Run("Fail to format tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig("StoreName", newstorage.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, `failed to format tag name "TagName1": tags formatting failure`)
	})
}

func TestFormattedProvider_GetStoreConfig(t *testing.T) {
	t.Run("Fail to deformat tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}},
			&mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		config, err := provider.GetStoreConfig("StoreName")
		require.EqualError(t, err, `failed to deformat tag name "TagName1" returned from the `+
			`underlying store: tags deformatting failure`)
		require.Empty(t, config)
	})
}

func TestFormattedProvider_Close(t *testing.T) {
	t.Run("Fail to close underlying provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}},
			&mockFormatter{})
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close underlying provider: close failure")
	})
}

func TestFormatStore_Put(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("KeyName", []byte("value"), newstorage.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
	})
	t.Run("Fail to format value", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormatValue: errors.New("value formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("KeyName", []byte("value"), newstorage.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, `failed to format value "value": value formatting failure`)
	})
	t.Run("Fail to format tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("KeyName", []byte("value"), newstorage.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, `failed to format tags: tags formatting failure`)
	})
}

func TestFormatStore_Get(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
		require.Nil(t, value)
	})
	t.Run("Fail to deformat value", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}}, &mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("KeyName")
		require.EqualError(t, err, `failed to deformat value "value" returned from the underlying store: `+
			`value deformatting failure`)
		require.Nil(t, value)
	})
}

func TestFormatStore_GetTags(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.GetTags("KeyName")
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
		require.Nil(t, value)
	})
	t.Run("Fail to deformat tags", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}},
			&mockFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.GetTags("KeyName")
		require.EqualError(t, err, "failed to deformat tags: tags deformatting failure")
		require.Nil(t, value)
	})
}

func TestFormatStore_GetBulk(t *testing.T) {
	t.Run("Fail to format key", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
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
		provider := formattedstore.NewProvider(mem.NewProvider(), &mockFormatter{})
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
		provider := formattedstore.NewProvider(&mockProvider{
			openStoreReturn: &mockStore{
				errQuery: errors.New("query failure"),
			},
		},
			&noOpFormatter{})
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
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
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
			&mockFormatter{errFormatKey: errors.New("key formatting failure")})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Batch([]newstorage.Operation{
			{
				Key:   "KeyName",
				Value: []byte("Value1"),
			},
		})
		require.EqualError(t, err, `failed to format key "KeyName": key formatting failure`)
	})
	t.Run("Fail to perform formatted operations in underlying store", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}}, &noOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Batch([]newstorage.Operation{
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
		provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}}, &noOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.EqualError(t, err, "failed to close underlying store: close failure")
	})
}

func TestFormattedIterator(t *testing.T) {
	provider := formattedstore.NewProvider(&mockProvider{openStoreReturn: &mockStore{}}, &noOpFormatter{})
	require.NotNil(t, provider)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)
	require.NotNil(t, store)

	iterator, err := store.Query("TagName1")
	require.NoError(t, err)

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
