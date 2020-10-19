/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatprovider

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

func TestNew(t *testing.T) {
	provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
	require.NoError(t, err)
	require.NotNil(t, provider)
}

func TestFormatProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.MockStoreProvider{ErrOpenStoreHandle: errTest}

		provider, err := New(&mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.EqualError(t, err, fmt.Errorf(failOpenUnderlyingStore, errTest).Error())
		require.Nil(t, store)
	})
}

func TestFormatProvider_CloseStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.CloseStore("testName")
		require.NoError(t, err)
	})
	t.Run("Fail to close store in underlying provider", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrCloseStore = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.CloseStore("testName")
		require.EqualError(t, err, fmt.Errorf(failCloseUnderlyingStore, errTest).Error())
	})
}

func TestFormatProvider_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.Close()
		require.NoError(t, err)
	})
	t.Run("Fail to close all stores in underlying provider", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrClose = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.Close()
		require.EqualError(t, err, fmt.Errorf(failCloseAllUnderlyingStores, errTest).Error())
	})
}

func Test_formatStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)
	})
	t.Run("Fail to encrypt structured document", func(t *testing.T) {
		errTest := errors.New("test error")

		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{errEncrypt: errTest})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failEncryptStructuredDocument, errTest).Error())
	})
	t.Run("Fail to marshal encrypted document", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		fmtStore, ok := store.(*formatStore)
		require.True(t, ok, "Failed to assert store as an *formatStore")
		fmtStore.marshal = failingMarshal

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failMarshalEncryptedDocument, errFailingMarshal).Error())
	})
	t.Run("Fail to put encrypted document bytes into underlying store", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failPutInUnderlyingStore, errTest).Error())
	})
}

func Test_formatStore_Get(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.NoError(t, err)
		require.Equal(t, "data", string(value))
	})
	t.Run("Fail to get encrypted document bytes from underlying store", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrGet = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.EqualError(t, err, fmt.Errorf(failGetFromUnderlyingStore, errTest).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to unmarshal encrypted document", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		fmtStore, ok := store.(*formatStore)
		require.True(t, ok, "Failed to assert store as an *formatStore")
		fmtStore.marshal = failingMarshal

		err = fmtStore.underlyingStore.Put("key", []byte("Not a valid Encrypted Document!"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.EqualError(t, err,
			fmt.Errorf(failUnmarshalEncryptedDocument,
				errors.New("invalid character 'N' looking for beginning of value")).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to decrypt encrypted document", func(t *testing.T) {
		errTest := errors.New("test error")

		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{errDecrypt: errTest})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.EqualError(t, err, fmt.Errorf(failDecryptEncryptedDocument, errTest).Error())
		require.Nil(t, value)
	})
	t.Run("Structured document is missing the payload key", func(t *testing.T) {
		provider, err := New(mem.NewProvider(),
			&mockDocumentProcessor{structuredDocToReturnOnDecrypt: &edv.StructuredDocument{}})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.EqualError(t, err, errPayloadKeyMissing.Error())
		require.Nil(t, value)
	})
	t.Run("Structured document payload cannot be asserted as []byte", func(t *testing.T) {
		content := make(map[string]interface{})
		content["payload"] = "not a []byte"

		unexpectedStructuredDocument := &edv.StructuredDocument{
			Content: content,
		}
		provider, err := New(mem.NewProvider(),
			&mockDocumentProcessor{structuredDocToReturnOnDecrypt: unexpectedStructuredDocument})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)

		value, err := store.Get("key")
		require.EqualError(t, err, errPayloadNotAssertableAsByteArray.Error())
		require.Nil(t, value)
	})
}

func Test_formatStore_Iterator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator := store.Iterator("", "")
		require.NotNil(t, iterator)
	})
}

func Test_formatStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete("key")
		require.NoError(t, err)
	})
	t.Run("Fail to delete underlying store", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrDelete = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete("key")
		require.EqualError(t, err, fmt.Errorf(failDeleteInUnderlyingStore, errTest).Error())
	})
}

func Test_formatStore_Query(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.QueryReturnValue = mockstorage.NewMockIterator(nil)

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator, err := store.Query("query")
		require.NoError(t, err)
		require.NotNil(t, iterator)
	})
	t.Run("Fail to query underlying store", func(t *testing.T) {
		errTest := errors.New("test error")

		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrQuery = errTest

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{})
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator, err := store.Query("query")
		require.EqualError(t, err, fmt.Errorf(failQueryUnderlyingStore, errTest).Error())
		require.Nil(t, iterator)
	})
}

type mockDocumentProcessor struct {
	errEncrypt                     error
	errDecrypt                     error
	structuredDocToReturnOnDecrypt *edv.StructuredDocument
}

func (m *mockDocumentProcessor) Encrypt(*edv.StructuredDocument) (*edv.EncryptedDocument, error) {
	return &edv.EncryptedDocument{}, m.errEncrypt
}

func (m *mockDocumentProcessor) Decrypt(*edv.EncryptedDocument) (*edv.StructuredDocument, error) {
	var structuredDocToReturn *edv.StructuredDocument

	if m.structuredDocToReturnOnDecrypt != nil {
		structuredDocToReturn = m.structuredDocToReturnOnDecrypt
	} else {
		content := make(map[string]interface{})
		content["payload"] = []byte("data")

		structuredDoc := edv.StructuredDocument{
			Content: content,
		}

		structuredDocToReturn = &structuredDoc
	}

	return structuredDocToReturn, m.errDecrypt
}

var errFailingMarshal = errors.New("failingMarshal always fails")

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}
