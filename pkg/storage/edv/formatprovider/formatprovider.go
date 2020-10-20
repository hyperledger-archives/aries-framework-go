/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatprovider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/documentprocessor"
)

const (
	failOpenUnderlyingStore        = "failed to open underlying store in FormatProvider: %w"
	failCloseUnderlyingStore       = "failed to close underlying store in FormatProvider: %w"
	failCloseAllUnderlyingStores   = "failed to close all underlying stores in FormatProvider: %w"
	failEncryptStructuredDocument  = "failed to encrypt structured document into a encrypted document: %w"
	failMarshalEncryptedDocument   = "failed to marshal encrypted document into bytes: %w"
	failPutInUnderlyingStore       = "failed to put encrypted document in underlying store in formatStore: %w"
	failGetFromUnderlyingStore     = "failed to get encrypted document bytes from underlying store in formatStore: %w"
	failUnmarshalEncryptedDocument = "failed to unmarshal encrypted document bytes into encrypted document struct: %w"
	failDecryptEncryptedDocument   = "failed to decrypt encrypted document into a structured document: %w"
	failDeleteInUnderlyingStore    = "failed to delete key-value pair in underlying store in formatStore: %w"
	failQueryUnderlyingStore       = "failed to query underlying store in formatStore: %w"
	payloadKey                     = "payload"
)

var (
	errPayloadKeyMissing = errors.New(`the structured document content did not contain the ` +
		`expected "payload" key`)
	errPayloadNotAssertableAsByteArray = errors.New("unable to assert the payload value as a []byte")
)

type marshalFunc func(interface{}) ([]byte, error)

// FormatProvider is an encrypted storage provider that uses EDV document models
// as defined in https://identity.foundation/secure-data-store/#data-model.
type FormatProvider struct {
	storeProvider     storage.Provider
	documentProcessor documentprocessor.DocumentProcessor
}

// New instantiates a new FormatProvider with the given underlying provider and EDV document processor.
// The underlying store provider determines where/how the data (in EDV Encrypted Document format) is actually stored. It
// only deals with data in encrypted form and cannot read the data flowing in or out of it.
// The EDV document processor handles encryption/decryption between structured documents and encrypted documents.
// It contains the necessary crypto functionality.
func New(underlyingProvider storage.Provider,
	encryptedDocumentProcessor documentprocessor.DocumentProcessor) (FormatProvider, error) {
	return FormatProvider{
		storeProvider:     underlyingProvider,
		documentProcessor: encryptedDocumentProcessor,
	}, nil
}

// OpenStore opens a store in the underlying provider with the given name and returns a handle to it.
func (p FormatProvider) OpenStore(name string) (storage.Store, error) {
	store, err := p.storeProvider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf(failOpenUnderlyingStore, err)
	}

	edvStore := formatStore{
		underlyingStore:   store,
		documentProcessor: p.documentProcessor,
		marshal:           json.Marshal,
	}

	return &edvStore, nil
}

// CloseStore closes the store with the given name in the underlying provider.
func (p FormatProvider) CloseStore(name string) error {
	err := p.storeProvider.CloseStore(name)
	if err != nil {
		return fmt.Errorf(failCloseUnderlyingStore, err)
	}

	return p.storeProvider.CloseStore(name)
}

// Close closes all stores created in the underlying store provider.
func (p FormatProvider) Close() error {
	err := p.storeProvider.Close()
	if err != nil {
		return fmt.Errorf(failCloseAllUnderlyingStores, err)
	}

	return p.storeProvider.Close()
}

type formatStore struct {
	underlyingStore   storage.Store
	documentProcessor documentprocessor.DocumentProcessor

	marshal marshalFunc
}

func (s formatStore) Put(k string, v []byte) error {
	content := make(map[string]interface{})
	content["payload"] = v

	structuredDoc := edv.StructuredDocument{
		ID:      k,
		Content: content,
	}

	encryptedDoc, err := s.documentProcessor.Encrypt(&structuredDoc)
	if err != nil {
		return fmt.Errorf(failEncryptStructuredDocument, err)
	}

	encryptedDocBytes, err := s.marshal(encryptedDoc)
	if err != nil {
		return fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	err = s.underlyingStore.Put(k, encryptedDocBytes)
	if err != nil {
		return fmt.Errorf(failPutInUnderlyingStore, err)
	}

	return nil
}

func (s formatStore) Get(k string) ([]byte, error) {
	encryptedDocBytes, err := s.underlyingStore.Get(k)
	if err != nil {
		return nil, fmt.Errorf(failGetFromUnderlyingStore, err)
	}

	var encryptedDocument edv.EncryptedDocument

	err = json.Unmarshal(encryptedDocBytes, &encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failUnmarshalEncryptedDocument, err)
	}

	structuredDocument, err := s.documentProcessor.Decrypt(&encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failDecryptEncryptedDocument, err)
	}

	payloadValue, ok := structuredDocument.Content[payloadKey]
	if !ok {
		return nil, errPayloadKeyMissing
	}

	payloadValueBytes, ok := payloadValue.([]byte)
	if !ok {
		return nil, errPayloadNotAssertableAsByteArray
	}

	return payloadValueBytes, nil
}

func (s formatStore) Iterator(startKey, endKey string) storage.StoreIterator {
	return s.underlyingStore.Iterator(startKey, endKey)
}

func (s formatStore) Delete(k string) error {
	err := s.underlyingStore.Delete(k)
	if err != nil {
		return fmt.Errorf(failDeleteInUnderlyingStore, err)
	}

	return nil
}

func (s formatStore) Query(query string) (storage.StoreIterator, error) {
	iterator, err := s.underlyingStore.Query(query)
	if err != nil {
		return nil, fmt.Errorf(failQueryUnderlyingStore, err)
	}

	return iterator, err
}
