/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batchedstore_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/newstorage/batchedstore"
	"github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/newstorage/mem"
	"github.com/hyperledger/aries-framework-go/component/newstorage/mock"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
	newstoragetest "github.com/hyperledger/aries-framework-go/test/newstorage"
)

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

func TestProvider_OpenStore(t *testing.T) {
	t.Run("Failed to open store in underlying provider", func(t *testing.T) {
		provider := batchedstore.NewProvider(&mock.Provider{ErrOpenStore: errors.New("open store failure")},
			3)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open store in underlying provider: open store failure")
		require.Nil(t, store)
	})
}

func TestProvider_Close(t *testing.T) {
	t.Run("Failed to close open store", func(t *testing.T) {
		provider := batchedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}}, 3)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.Close()
		require.EqualError(t, err, `failed to close open store with name "storename": `+
			`failed to close underlying store: close failure`)
	})
	t.Run("Failed to close underlying provider", func(t *testing.T) {
		provider := batchedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}}, 3)
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close underlying provider: close failure")
	})
}

func TestCommon(t *testing.T) {
	t.Run("With batch size set to 0", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 0)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{}), 0)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With batch size set to 1", func(t *testing.T) { // Should work the same as size 0 above
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 1)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{}), 1)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With batch size set to 2", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 2)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{}), 2)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With batch size set to 10", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 10)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{}), 10)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With batch size set to 100", func(t *testing.T) {
		t.Run("With in-memory storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(mem.NewProvider(), 100)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With formatted storage as underlying provider", func(t *testing.T) {
			provider := batchedstore.NewProvider(
				formattedstore.NewProvider(mem.NewProvider(), &base64Formatter{}), 100)
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
}
