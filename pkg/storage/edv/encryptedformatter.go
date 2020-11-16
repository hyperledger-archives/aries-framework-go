/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

const (
	failGenerateEDVCompatibleID   = "failed to generate EDV compatible ID: %w"
	failMarshalStructuredDocument = "failed to marshal structured document into bytes: %w"
	failEncryptStructuredDocument = "failed to encrypt structured document into JWE form: %w"
	failJWESerialize              = "failed to serialize JWE: %w"

	failDeserializeJWE              = "failed to deserialize JWE: %w"
	failDecryptJWE                  = "failed to decrypt JWE: %w"
	failUnmarshalStructuredDocument = "failed to unmarshal structured document: %w"

	payloadContentKey     = "payload"
	originalKeyContentKey = "originalKey"
)

var (
	errPayloadKeyMissing = errors.New(`the structured document content did not contain the ` +
		`expected "` + payloadContentKey + `" key`)
	errOriginalKeyMissing = errors.New(`the structured document content did not contain the ` +
		`expected "` + originalKeyContentKey + `" key`)
	errPayloadNotAssertableAsString     = errors.New("unable to assert the payload value as a string")
	errOriginalKeyNotAssertableAsString = errors.New("failed to assert the original key value as a string")
)

type marshalFunc func(interface{}) ([]byte, error)

// EncryptedFormatter uses Aries crypto to encrypt and decrypt between
// Structured Documents and Encrypted Documents.
type EncryptedFormatter struct {
	jweEncrypter    jose.Encrypter
	jweDecrypter    jose.Decrypter
	marshal         marshalFunc
	randomBytesFunc generateRandomBytesFunc
}

// NewEncryptedFormatter returns a new instance of an EncryptedFormatter.
func NewEncryptedFormatter(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter) *EncryptedFormatter {
	return &EncryptedFormatter{
		jweEncrypter:    jweEncrypter,
		jweDecrypter:    jweDecrypter,
		marshal:         json.Marshal,
		randomBytesFunc: rand.Read,
	}
}

// FormatPair encrypts k and v into encrypted document format.
func (f *EncryptedFormatter) FormatPair(k string, v []byte) ([]byte, error) {
	content := make(map[string]interface{})
	content[originalKeyContentKey] = k
	content[payloadContentKey] = string(v)

	structuredDocumentID, err := generateEDVCompatibleID(f.randomBytesFunc)
	if err != nil {
		return nil, fmt.Errorf(failGenerateEDVCompatibleID, err)
	}

	structuredDocument := models.StructuredDocument{
		ID:      structuredDocumentID,
		Content: content,
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

	encryptedDocument := models.EncryptedDocument{
		ID:  structuredDocument.ID,
		JWE: []byte(serializedJWE),
	}

	encryptedDocumentBytes, err := f.marshal(encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf(failMarshalEncryptedDocument, err)
	}

	return encryptedDocumentBytes, nil
}

// ParsePair decrypts encryptedDocumentBytes and returns the original key and the decrypted data.
func (f *EncryptedFormatter) ParsePair(encryptedDocumentBytes []byte) (string, []byte, error) {
	structuredDocument, err := f.getStructuredDocFromEncryptedDoc(encryptedDocumentBytes)
	if err != nil {
		return "", nil, fmt.Errorf(failGetStructuredDocFromEncryptedDocBytes, err)
	}

	payloadValue, ok := structuredDocument.Content[payloadContentKey]
	if !ok {
		return "", nil, errPayloadKeyMissing
	}

	payloadValueString, ok := payloadValue.(string)
	if !ok {
		return "", nil, errPayloadNotAssertableAsString
	}

	originalKeyValue, ok := structuredDocument.Content[originalKeyContentKey]
	if !ok {
		return "", nil, errOriginalKeyMissing
	}

	originalKeyValueString, ok := originalKeyValue.(string)
	if !ok {
		return "", nil, errOriginalKeyNotAssertableAsString
	}

	return originalKeyValueString, []byte(payloadValueString), nil
}

func (f *EncryptedFormatter) getStructuredDocFromEncryptedDoc(
	encryptedDocBytes []byte) (models.StructuredDocument, error) {
	var encryptedDocument models.EncryptedDocument

	err := json.Unmarshal(encryptedDocBytes, &encryptedDocument)
	if err != nil {
		return models.StructuredDocument{}, fmt.Errorf(failUnmarshalValueIntoEncryptedDocument, err)
	}

	encryptedJWE, err := jose.Deserialize(string(encryptedDocument.JWE))
	if err != nil {
		return models.StructuredDocument{}, fmt.Errorf(failDeserializeJWE, err)
	}

	structuredDocumentBytes, err := f.jweDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return models.StructuredDocument{}, fmt.Errorf(failDecryptJWE, err)
	}

	var structuredDocument models.StructuredDocument

	err = json.Unmarshal(structuredDocumentBytes, &structuredDocument)
	if err != nil {
		return models.StructuredDocument{}, fmt.Errorf(failUnmarshalStructuredDocument, err)
	}

	return structuredDocument, nil
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
