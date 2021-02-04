/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/newstorage/edv"
	"github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/newstorage/formattedstore/exampleformatters"
	"github.com/hyperledger/aries-framework-go/component/newstorage/mem"
	"github.com/hyperledger/aries-framework-go/component/newstorage/mock"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
	newstoragetest "github.com/hyperledger/aries-framework-go/test/newstorage"
)

type mockFormatter struct {
	errFormat error
}

func (m *mockFormatter) Format(string, []byte, ...newstorage.Tag) (string, []byte, []newstorage.Tag, error) {
	return "", nil, nil, m.errFormat
}

func (m *mockFormatter) Deformat(string, []byte, ...newstorage.Tag) (string, []byte, []newstorage.Tag, error) {
	return "", nil, nil, errors.New("key, value or tags deformatting failure")
}

func TestCommon(t *testing.T) {
	t.Run("With no-op formatter", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{})
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{},
				formattedstore.WithCacheProvider(mem.NewProvider()))
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With base64 formatter", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.Base64Formatter{})
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.Base64Formatter{},
				formattedstore.WithCacheProvider(mem.NewProvider()))
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
	})
	t.Run("With EDV Encrypted Formatter", func(t *testing.T) {
		t.Run("Without cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), createEncryptedFormatter(t))
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
		t.Run("With cache", func(t *testing.T) {
			provider := formattedstore.NewProvider(mem.NewProvider(), createEncryptedFormatter(t),
				formattedstore.WithCacheProvider(mem.NewProvider()))
			require.NotNil(t, provider)

			newstoragetest.TestAll(t, provider)
		})
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
	t.Run("Fail to open store in cache provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{},
			formattedstore.WithCacheProvider(&mock.Provider{ErrOpenStore: errors.New("open store failure")}))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.EqualError(t, err, "failed to open cache store in cache provider: open store failure")
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

		err = provider.SetStoreConfig("StoreName", newstorage.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, "failed to format tag names: tags formatting failure")
	})
	t.Run("Fail to set store config in cache provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{},
			formattedstore.WithCacheProvider(
				&mock.Provider{ErrSetStoreConfig: errors.New("set store config failure")}))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig("StoreName", newstorage.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, "failed to set store configuration via cache provider: "+
			"set store config failure")
	})
	t.Run("Fail to store config in store config store", func(t *testing.T) {
		provider := formattedstore.NewProvider(
			&mock.Provider{OpenStoreReturn: &mock.Store{ErrPut: errors.New("put failure")}},
			&exampleformatters.NoOpFormatter{})
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig("StoreName", newstorage.StoreConfiguration{TagNames: []string{"TagName1"}})
		require.EqualError(t, err, "failed to store config in store config store: "+
			"failed to put formatted data in underlying store: put failure")
	})
}

func TestFormattedProvider_GetStoreConfig(t *testing.T) {
	t.Run("Unexpected failure while getting config from cache store", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(),
			&exampleformatters.NoOpFormatter{}, formattedstore.WithCacheProvider(&mock.Provider{
				ErrGetStoreConfig: errors.New("unexpected get store config failure"),
			}))
		require.NotNil(t, provider)

		config, err := provider.GetStoreConfig("StoreName")
		require.EqualError(t, err, "unexpected failure while getting config from cache store: "+
			"unexpected get store config failure")
		require.Empty(t, config)
	})
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
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
			&mockFormatter{})
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close underlying provider: close failure")
	})
	t.Run("Fail to close cache provider", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{},
			formattedstore.WithCacheProvider(&mock.Provider{}))
		require.NotNil(t, provider)

		err := provider.Close()
		require.EqualError(t, err, "failed to close cache provider: close failure")
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

		err = store.Put("KeyName", []byte("value"), newstorage.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, "failed to format data: formatting failure")
	})
	t.Run("Fail to put data in cache store", func(t *testing.T) {
		provider := formattedstore.NewProvider(mem.NewProvider(), &exampleformatters.NoOpFormatter{},
			formattedstore.WithCacheProvider(
				&mock.Provider{OpenStoreReturn: &mock.Store{ErrPut: errors.New("put failure")}}))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("KeyName", []byte("value"), newstorage.Tag{Name: "TagName1", Value: "TagValue1"})
		require.EqualError(t, err, `failed to put data in cache store: put failure`)
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
	t.Run("Fail to put retrieved data in cache store", func(t *testing.T) {
		// First get sample data in the underlying provider.
		underlyingProvider := mem.NewProvider()

		underlyingStore, err := underlyingProvider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, underlyingStore)

		err = underlyingStore.Put("KeyName", []byte("value"))
		require.NoError(t, err)

		provider := formattedstore.NewProvider(underlyingProvider, &exampleformatters.NoOpFormatter{},
			formattedstore.WithCacheProvider(
				&mock.Provider{OpenStoreReturn: &mock.Store{
					ErrGet: newstorage.ErrDataNotFound, ErrPut: errors.New("put error"),
				}}))
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)
		require.NotNil(t, store)

		// Attempt retrieving that sample data we put in the underlying provider earlier.
		value, err := store.Get("KeyName")
		require.EqualError(t, err, "failed to put the newly retrieved value into the cache store: put error")
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

		err = store.Batch([]newstorage.Operation{
			{
				Key:   "KeyName",
				Value: []byte("Value1"),
			},
		})
		require.EqualError(t, err, "failed to format data: key formatting failure")
	})
	t.Run("Fail to perform formatted operations in underlying store", func(t *testing.T) {
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
			&exampleformatters.NoOpFormatter{})
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
		provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
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
	provider := formattedstore.NewProvider(&mock.Provider{OpenStoreReturn: &mock.Store{}},
		&exampleformatters.NoOpFormatter{})
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

func createEncryptedFormatter(t *testing.T) *edv.EncryptedFormatter {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	formatter := edv.NewEncryptedFormatter(encrypter, decrypter, createMACCrypto(t))
	require.NotNil(t, formatter)

	return formatter
}

func createEncrypterAndDecrypter(t *testing.T) (*jose.JWEEncrypt, *jose.JWEDecrypt) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	keyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	kmsSvc := &mockkms.KeyManager{
		GetKeyValue: keyHandle,
	}

	pubKH, err := keyHandle.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "EDVEncryptedDocument", "", nil,
		[]*cryptoapi.PublicKey{ecPubKey}, cryptoSvc)
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, cryptoSvc, kmsSvc)

	return encrypter, decrypter
}

func createMACCrypto(t *testing.T) *edv.MACCrypto {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	return edv.NewMACCrypto(kh, crypto)
}
