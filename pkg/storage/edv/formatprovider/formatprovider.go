/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatprovider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
)

const (
	failComputeMACIndexName        = "failed to compute MAC for index name: %w"
	failOpenUnderlyingStore        = "failed to open underlying store in FormatProvider: %w"
	failCloseUnderlyingStore       = "failed to close underlying store in FormatProvider: %w"
	failCloseAllUnderlyingStores   = "failed to close all underlying stores in FormatProvider: %w"
	failGenerateEDVCompatibleID    = "failed to generate EDV compatible ID: %w"
	failCreateIndexedAttribute     = "failed to create indexed attribute: %w"
	failToComputeMACIndexValue     = "failed to compute MAC for index value: %w"
	failEncryptStructuredDocument  = "failed to encrypt structured document into a encrypted document: %w"
	failMarshalEncryptedDocument   = "failed to marshal encrypted document into bytes: %w"
	failPutInUnderlyingStore       = "failed to put encrypted document in underlying store in formatStore: %w"
	failUnmarshalEncryptedDocument = "failed to unmarshal encrypted document bytes into encrypted document struct: %w"
	failDecryptEncryptedDocument   = "failed to decrypt encrypted document into a structured document: %w"
	failDeleteInUnderlyingStore    = "failed to delete key-value pair in underlying store in formatStore: %w"
	failQueryUnderlyingStore       = "failed to query underlying store in formatStore: %w"

	payloadKey  = "payload"
	keyIndexKey = "indexKey"
)

var (
	errPayloadKeyMissing = errors.New(`the structured document content did not contain the ` +
		`expected "payload" key`)
	errPayloadNotAssertableAsString = errors.New("unable to assert the payload value as a string")
)

type marshalFunc func(interface{}) ([]byte, error)

// MACDigester represents a type that can compute MACs.
type MACDigester interface {
	ComputeMAC(data []byte, kh interface{}) ([]byte, error)
}

// MACCrypto is used for computing MACs.
type MACCrypto struct {
	kh          interface{}
	macDigester MACDigester
}

// ComputeMAC computes a MAC for data using a matching MAC primitive in kh.
func (m *MACCrypto) ComputeMAC(data string) (string, error) {
	dataMAC, err := m.macDigester.ComputeMAC([]byte(data), m.kh)
	return string(dataMAC), err
}

// DocumentProcessor represents a type that can encrypt and decrypt between
// Structured Documents and Encrypted Documents.
type DocumentProcessor interface {
	Encrypt(*edv.StructuredDocument, []edv.IndexedAttributeCollection) (*edv.EncryptedDocument, error)
	Decrypt(*edv.EncryptedDocument) (*edv.StructuredDocument, error)
}

// FormatProvider is an encrypted storage provider that uses EDV document models
// as defined in https://identity.foundation/secure-data-store/#data-model.
// TODO (#2273): Generalize this to allow for other encrypted formats.
type FormatProvider struct {
	storeProvider            storage.Provider
	documentProcessor        DocumentProcessor
	macCrypto                *MACCrypto
	indexKeyMACBase64Encoded string
	marshal                  marshalFunc
	generateRandomBytesFunc  generateRandomBytesFunc
}

// New instantiates a new FormatProvider with the given underlying provider and EDV document processor.
// The underlying store provider determines where/how the data (in EDV Encrypted Document format) is actually stored. It
// only deals with data in encrypted form and cannot read the data flowing in or out of it.
// The EDV document processor handles encryption/decryption between structured documents and encrypted documents.
// It contains the necessary crypto functionality.
func New(underlyingProvider storage.Provider, encryptedDocumentProcessor DocumentProcessor,
	macCrypto *MACCrypto) (*FormatProvider, error) {
	indexKeyMAC, err := macCrypto.ComputeMAC(keyIndexKey)
	if err != nil {
		return nil, fmt.Errorf(failComputeMACIndexName, err)
	}

	return &FormatProvider{
		storeProvider:            underlyingProvider,
		documentProcessor:        encryptedDocumentProcessor,
		macCrypto:                macCrypto,
		indexKeyMACBase64Encoded: base64.URLEncoding.EncodeToString([]byte(indexKeyMAC)),
		marshal:                  json.Marshal,
		generateRandomBytesFunc:  rand.Read,
	}, nil
}

// OpenStore opens a store in the underlying provider with the given name and returns a handle to it.
func (p FormatProvider) OpenStore(name string) (storage.Store, error) {
	store, err := p.storeProvider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf(failOpenUnderlyingStore, err)
	}

	edvStore := formatStore{
		underlyingStore:          store,
		documentProcessor:        p.documentProcessor,
		macCrypto:                p.macCrypto,
		indexKeyMACBase64Encoded: p.indexKeyMACBase64Encoded,
		marshal:                  p.marshal,
		randomBytesFunc:          p.generateRandomBytesFunc,
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
	underlyingStore          storage.Store
	documentProcessor        DocumentProcessor
	macCrypto                *MACCrypto
	indexKeyMACBase64Encoded string
	marshal                  marshalFunc
	randomBytesFunc          generateRandomBytesFunc
}

func (s formatStore) Put(k string, v []byte) error {
	content := make(map[string]interface{})
	content[payloadKey] = string(v)

	structuredDocumentID, err := generateEDVCompatibleID(s.randomBytesFunc)
	if err != nil {
		return fmt.Errorf(failGenerateEDVCompatibleID, err)
	}

	structuredDoc := edv.StructuredDocument{
		ID:      structuredDocumentID,
		Content: content,
	}

	indexedAttributeCollections, err := s.createIndexedAttribute(k)
	if err != nil {
		return fmt.Errorf(failCreateIndexedAttribute, err)
	}

	encryptedDoc, err := s.documentProcessor.Encrypt(&structuredDoc, indexedAttributeCollections)
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
	indexValueMAC, err := s.macCrypto.ComputeMAC(k)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC for index value: %w", err)
	}

	matchingDocumentsIterator, err :=
		s.underlyingStore.Query(s.indexKeyMACBase64Encoded, base64.URLEncoding.EncodeToString([]byte(indexValueMAC)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	if !matchingDocumentsIterator.Next() {
		return nil, fmt.Errorf("query of underlying store returned no results: %w", storage.ErrDataNotFound)
	}

	encryptedDocumentBytes := matchingDocumentsIterator.Value()

	err = matchingDocumentsIterator.Error()

	if err != nil {
		return nil, fmt.Errorf("failure while iterating over matching documents: %w", err)
	}

	// Ensure that only one document was returned.
	// The index name + value pair is supposed to be unique. If multiple documents match the query, something has
	// gone very wrong with the database's state.
	if matchingDocumentsIterator.Next() {
		return nil, errors.New("encrypted index query for document key returned multiple documents." +
			" Only one document was expected")
	}

	var encryptedDocument edv.EncryptedDocument

	err = json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
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

	payloadValueString, ok := payloadValue.(string)
	if !ok {
		return nil, errPayloadNotAssertableAsString
	}

	return []byte(payloadValueString), nil
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

func (s formatStore) Query(attributeName, attributeValue string) (storage.StoreIterator, error) {
	iterator, err := s.underlyingStore.Query(attributeName, attributeValue)
	if err != nil {
		return nil, fmt.Errorf(failQueryUnderlyingStore, err)
	}

	return iterator, err
}

type generateRandomBytesFunc func([]byte) (int, error)

func generateEDVCompatibleID(generateRandomBytes generateRandomBytesFunc) (string, error) {
	randomBytes := make([]byte, 16)

	_, err := generateRandomBytes(randomBytes)
	if err != nil {
		return "", err
	}

	base58EncodedUUID := base58.Encode(randomBytes)

	return base58EncodedUUID, nil
}

func (s formatStore) createIndexedAttribute(k string) ([]edv.IndexedAttributeCollection, error) {
	indexValueMAC, err := s.macCrypto.ComputeMAC(k)
	if err != nil {
		return nil, fmt.Errorf(failToComputeMACIndexValue, err)
	}

	indexedAttribute := edv.IndexedAttribute{
		Name:   s.indexKeyMACBase64Encoded,
		Value:  base64.URLEncoding.EncodeToString([]byte(indexValueMAC)),
		Unique: true,
	}

	indexedAttributeCollection := edv.IndexedAttributeCollection{
		HMAC:              edv.IDTypePair{},
		IndexedAttributes: []edv.IndexedAttribute{indexedAttribute},
	}

	indexedAttributeCollections := []edv.IndexedAttributeCollection{indexedAttributeCollection}

	return indexedAttributeCollections, nil
}
