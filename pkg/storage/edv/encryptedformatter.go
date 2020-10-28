/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

const (
	failComputeMACIndexName         = "failed to compute MAC for index name: %w"
	failGenerateEDVCompatibleID     = "failed to generate EDV compatible ID: %w"
	failCreateIndexedAttribute      = "failed to create indexed attribute: %w"
	failMarshalStructuredDocument   = "failed to marshal structured document into bytes: %w"
	failEncryptStructuredDocument   = "failed to encrypt structured document into JWE form: %w"
	failJWESerialize                = "failed to serialize JWE: %w"
	failMarshalEncryptedDocument    = "failed to marshal encrypted document into bytes: %w"
	failUnmarshalEncryptedDocument  = "failed to unmarshal encrypted document bytes: %w"
	failDeserializeJWE              = "failed to deserialize JWE: %w"
	failDecryptJWE                  = "failed to decrypt JWE: %w"
	failUnmarshalStructuredDocument = "failed to unmarshal structured document: %w"
	failToComputeMACIndexValue      = "failed to compute MAC for index value: %w"

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

// NewMACCrypto returns a new instance of a MACCrypto.
func NewMACCrypto(kh interface{}, macDigester MACDigester) *MACCrypto {
	return &MACCrypto{
		kh:          kh,
		macDigester: macDigester,
	}
}

// EncryptedFormatter uses Aries crypto to encrypt and decrypt between
// Structured Documents and Encrypted Documents.
type EncryptedFormatter struct {
	jweEncrypter             jose.Encrypter
	jweDecrypter             jose.Decrypter
	macCrypto                *MACCrypto
	indexKeyMACBase64Encoded string
	marshal                  marshalFunc
	randomBytesFunc          generateRandomBytesFunc
}

// NewEncryptedFormatter returns a new instance of an EncryptedFormatter.
func NewEncryptedFormatter(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter,
	macCrypto *MACCrypto) (*EncryptedFormatter, error) {
	indexKeyMAC, err := macCrypto.ComputeMAC(keyIndexKey)
	if err != nil {
		return nil, fmt.Errorf(failComputeMACIndexName, err)
	}

	return &EncryptedFormatter{
		jweEncrypter:             jweEncrypter,
		jweDecrypter:             jweDecrypter,
		macCrypto:                macCrypto,
		indexKeyMACBase64Encoded: base64.URLEncoding.EncodeToString([]byte(indexKeyMAC)),
		marshal:                  json.Marshal,
		randomBytesFunc:          rand.Read,
	}, nil
}

// FormatPair encrypts v into encrypted document format.
// An encrypted index attribute based on k is attached to the encrypted document.
// The encrypted document is returned in marshalled form.
func (f *EncryptedFormatter) FormatPair(k string, v []byte) ([]byte, error) {
	content := make(map[string]interface{})
	content[payloadKey] = string(v)

	structuredDocumentID, err := generateEDVCompatibleID(f.randomBytesFunc)
	if err != nil {
		return nil, fmt.Errorf(failGenerateEDVCompatibleID, err)
	}

	structuredDocument := StructuredDocument{
		ID:      structuredDocumentID,
		Content: content,
	}

	indexedAttributeCollections, err := f.createIndexedAttribute(k)
	if err != nil {
		return nil, fmt.Errorf(failCreateIndexedAttribute, err)
	}

	structuredDocumentBytes, err := f.marshal(structuredDocument)
	if err != nil {
		return nil, fmt.Errorf(failMarshalStructuredDocument, err)
	}

	jwe, err := f.jweEncrypter.Encrypt(structuredDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf(failEncryptStructuredDocument, err)
	}

	serializedJWE, err := jwe.FullSerialize(func(i interface{}) ([]byte, error) {
		return f.marshal(i)
	})
	if err != nil {
		return nil, fmt.Errorf(failJWESerialize, err)
	}

	encryptedDocument := EncryptedDocument{
		ID:                          structuredDocument.ID,
		IndexedAttributeCollections: indexedAttributeCollections,
		JWE:                         []byte(serializedJWE),
	}

	encryptedDocumentBytes, err := f.marshal(encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	return encryptedDocumentBytes, nil
}

// ParseValue decrypts encryptedDocumentBytes and returns the decrypted data.
func (f *EncryptedFormatter) ParseValue(encryptedDocumentBytes []byte) ([]byte, error) {
	var encryptedDocument EncryptedDocument

	err := json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failUnmarshalEncryptedDocument, err)
	}

	encryptedJWE, err := jose.Deserialize(string(encryptedDocument.JWE))
	if err != nil {
		return nil, fmt.Errorf(failDeserializeJWE, err)
	}

	structuredDocumentBytes, err := f.jweDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return nil, fmt.Errorf(failDecryptJWE, err)
	}

	var structuredDocument StructuredDocument

	err = json.Unmarshal(structuredDocumentBytes, &structuredDocument)
	if err != nil {
		return nil, fmt.Errorf(failUnmarshalStructuredDocument, err)
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

func (f *EncryptedFormatter) createIndexedAttribute(k string) ([]IndexedAttributeCollection, error) {
	indexValueMAC, err := f.macCrypto.ComputeMAC(k)
	if err != nil {
		return nil, fmt.Errorf(failToComputeMACIndexValue, err)
	}

	indexedAttribute := IndexedAttribute{
		Name:   f.indexKeyMACBase64Encoded,
		Value:  base64.URLEncoding.EncodeToString([]byte(indexValueMAC)),
		Unique: true,
	}

	indexedAttributeCollection := IndexedAttributeCollection{
		HMAC:              IDTypePair{},
		IndexedAttributes: []IndexedAttribute{indexedAttribute},
	}

	indexedAttributeCollections := []IndexedAttributeCollection{indexedAttributeCollection}

	return indexedAttributeCollections, nil
}

type generateRandomBytesFunc func([]byte) (int, error)

func generateEDVCompatibleID(generateRandomBytes generateRandomBytesFunc) (string, error) {
	randomBytes := make([]byte, 16)

	_, err := generateRandomBytes(randomBytes)
	if err != nil {
		return "", err
	}

	return base58.Encode(randomBytes), nil
}
