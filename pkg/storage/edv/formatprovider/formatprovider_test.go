/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/documentprocessor"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

var errTest = errors.New("test error")

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to compute MAC", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t),
			&MACCrypto{
				kh:          nil,
				macDigester: &mockcrypto.Crypto{ComputeMACErr: errTest},
			})
		require.EqualError(t, err, fmt.Errorf(failComputeMACIndexName, errTest).Error())
		require.Nil(t, provider)
	})
}

func TestFormatProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Fail to open store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.MockStoreProvider{ErrOpenStoreHandle: errTest}

		provider, err := New(&mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.EqualError(t, err, fmt.Errorf(failOpenUnderlyingStore, errTest).Error())
		require.Nil(t, store)
	})
}

func TestFormatProvider_CloseStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.CloseStore("testName")
		require.NoError(t, err)
	})
	t.Run("Fail to close store in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrCloseStore = errTest

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.CloseStore("testName")
		require.EqualError(t, err, fmt.Errorf(failCloseUnderlyingStore, errTest).Error())
	})
}

func TestFormatProvider_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.Close()
		require.NoError(t, err)
	})
	t.Run("Fail to close all stores in underlying provider", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.ErrClose = errTest

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.Close()
		require.EqualError(t, err, fmt.Errorf(failCloseAllUnderlyingStores, errTest).Error())
	})
}

func Test_formatStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.NoError(t, err)
	})
	t.Run("Fail to create indexed attribute", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		fmtStore, ok := store.(*formatStore)
		require.True(t, ok, "Failed to assert store as an *formatStore")
		fmtStore.macCrypto = &MACCrypto{
			kh:          nil,
			macDigester: &mockcrypto.Crypto{ComputeMACErr: errTest},
		}

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err,
			fmt.Errorf(failCreateIndexedAttribute, fmt.Errorf(failToComputeMACIndexValue, errTest)).Error())
	})
	t.Run("Fail to generate EDV compatible ID", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)
		provider.generateRandomBytesFunc = failingGenerateRandomBytesFunc

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failGenerateEDVCompatibleID, errGenerateRandomBytes).Error())
	})
	t.Run("Fail to encrypt structured document", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), &mockDocumentProcessor{errEncrypt: errTest}, newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failEncryptStructuredDocument, errTest).Error())
	})
	t.Run("Fail to marshal encrypted document", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)
		provider.marshal = failingMarshal

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("data"))
		require.EqualError(t, err, fmt.Errorf(failMarshalEncryptedDocument, errFailingMarshal).Error())
	})
	t.Run("Fail to put encrypted document bytes into underlying store", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrPut = errTest

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
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
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
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
	t.Run("Fail to unmarshal encrypted document", func(t *testing.T) {
		mockIteratorBatch := [][]string{{"key", "Not a valid Encrypted Document!"}}
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.QueryReturnValue = mockstorage.NewMockIterator(mockIteratorBatch)

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{}, newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("key")
		require.EqualError(t, err,
			fmt.Errorf(failUnmarshalEncryptedDocument,
				errors.New("invalid character 'N' looking for beginning of value")).Error())
		require.Nil(t, value)
	})
	t.Run("Fail to decrypt encrypted document", func(t *testing.T) {
		encryptedDocument := edv.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		mockIteratorBatch := [][]string{{"key", string(encryptedDocumentBytes)}}
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.QueryReturnValue = mockstorage.NewMockIterator(mockIteratorBatch)

		provider, err := New(mockStoreProvider, &mockDocumentProcessor{errDecrypt: errTest}, newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("key")
		require.EqualError(t, err, fmt.Errorf(failDecryptEncryptedDocument, errTest).Error())
		require.Nil(t, value)
	})
	t.Run("Structured document is missing the payload key", func(t *testing.T) {
		encryptedDocument := edv.EncryptedDocument{}

		encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
		require.NoError(t, err)

		mockIteratorBatch := [][]string{{"key", string(encryptedDocumentBytes)}}
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.QueryReturnValue = mockstorage.NewMockIterator(mockIteratorBatch)

		provider, err := New(mockStoreProvider,
			&mockDocumentProcessor{structuredDocToReturnOnDecrypt: &edv.StructuredDocument{}}, newMACCrypto(t))
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
	t.Run("Structured document payload cannot be asserted as string", func(t *testing.T) {
		mockIteratorBatch := [][]string{{"key", getBarebonesMarshalledEncryptedDocument(t)}}
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.QueryReturnValue = mockstorage.NewMockIterator(mockIteratorBatch)

		content := make(map[string]interface{})
		content["payload"] = []byte("data")

		structuredDocumentWithByteArrayPayload := &edv.StructuredDocument{
			Content: content,
		}

		provider, err := New(mockStoreProvider,
			&mockDocumentProcessor{structuredDocToReturnOnDecrypt: structuredDocumentWithByteArrayPayload},
			newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		value, err := store.Get("key")
		require.EqualError(t, err, errPayloadNotAssertableAsString.Error())
		require.Nil(t, value)
	})
}

func getBarebonesMarshalledEncryptedDocument(t *testing.T) string {
	encryptedDocument := edv.EncryptedDocument{}

	encryptedDocumentBytes, err := json.Marshal(encryptedDocument)
	require.NoError(t, err)

	return string(encryptedDocumentBytes)
}

func Test_formatStore_Range(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
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
		provider, err := New(mem.NewProvider(), createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Delete("key")
		require.NoError(t, err)
	})
	t.Run("Fail to delete underlying store", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrDelete = errTest

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
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

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator, err := store.Query("", "")
		require.NoError(t, err)
		require.NotNil(t, iterator)
	})
	t.Run("Fail to query underlying store", func(t *testing.T) {
		mockStoreProvider := mockstorage.NewMockStoreProvider()
		mockStoreProvider.Store.ErrQuery = errTest

		provider, err := New(mockStoreProvider, createDocumentProcessor(t), newMACCrypto(t))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("testName")
		require.NoError(t, err)
		require.NotNil(t, store)

		iterator, err := store.Query("", "")
		require.EqualError(t, err, fmt.Errorf(failQueryUnderlyingStore, errTest).Error())
		require.Nil(t, iterator)
	})
}

type mockDocumentProcessor struct {
	errEncrypt                     error
	errDecrypt                     error
	structuredDocToReturnOnDecrypt *edv.StructuredDocument
}

func (m *mockDocumentProcessor) Encrypt(*edv.StructuredDocument,
	[]edv.IndexedAttributeCollection) (*edv.EncryptedDocument, error) {
	return &edv.EncryptedDocument{}, m.errEncrypt
}

func (m *mockDocumentProcessor) Decrypt(*edv.EncryptedDocument) (*edv.StructuredDocument, error) {
	return m.structuredDocToReturnOnDecrypt, m.errDecrypt
}

var errFailingMarshal = errors.New("failingMarshal always fails")

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

var errGenerateRandomBytes = errors.New("failingGenerateRandomBytesFunc always fails")

func failingGenerateRandomBytesFunc([]byte) (int, error) {
	return -1, errGenerateRandomBytes
}

func createDocumentProcessor(t *testing.T) DocumentProcessor {
	encrypter, decrypter := createEncrypterAndDecrypter(t)

	documentProcessor := documentprocessor.New(encrypter, decrypter)
	require.NotNil(t, documentProcessor)

	return documentProcessor
}

func createEncrypterAndDecrypter(t *testing.T) (*jose.JWEEncrypt, *jose.JWEDecrypt) {
	keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	pubKH, err := keyHandle.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	ecPubKey := new(composite.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	require.NoError(t, err)

	encrypter, err := jose.NewJWEEncrypt(jose.A256GCM, "EDVEncryptedDocument", "", nil,
		[]*composite.PublicKey{ecPubKey})
	require.NoError(t, err)

	decrypter := jose.NewJWEDecrypt(nil, keyHandle)

	return encrypter, decrypter
}

func newMACCrypto(t *testing.T) *MACCrypto {
	crypto, err := tinkcrypto.New()
	require.NoError(t, err)

	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)
	require.NotNil(t, kh)

	return &MACCrypto{macDigester: crypto, kh: kh}
}
