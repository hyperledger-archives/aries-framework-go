/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv/models"
)

const (
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
	jweEncrypter jose.Encrypter
	jweDecrypter jose.Decrypter
	marshal      marshalFunc
	macCrypto    *MACCrypto
}

// NewEncryptedFormatter returns a new instance of an EncryptedFormatter.
func NewEncryptedFormatter(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter,
	macCrypto *MACCrypto) *EncryptedFormatter {
	return &EncryptedFormatter{
		jweEncrypter: jweEncrypter,
		jweDecrypter: jweDecrypter,
		marshal:      json.Marshal,
		macCrypto:    macCrypto,
	}
}

// FormatPair encrypts k and v into encrypted document format.
func (f *EncryptedFormatter) FormatPair(k string, v []byte) ([]byte, error) {
	content := make(map[string]interface{})
	content[originalKeyContentKey] = k
	content[payloadContentKey] = string(v)

	structuredDocumentID, err := f.GenerateEDVDocumentID(k)
	if err != nil {
		return nil, err
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

// GenerateEDVDocumentID generates the EDV document ID based on k and the MAC crypto key.
// TODO (#2376) Revisit how we're generating EDV document IDs, since it's technically not 100% in line with the spec.
//  (Spec requires randomly generated IDs)
func (f *EncryptedFormatter) GenerateEDVDocumentID(k string) (string, error) {
	hashKey, err := f.macCrypto.ComputeMAC(k)
	if err != nil {
		return "", err
	}

	return base58.Encode([]byte(hashKey[0:16])), nil
}
