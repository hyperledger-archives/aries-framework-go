/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package documentprocessor

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
)

const (
	failMarshalStructuredDocument   = "failed to marshal structured document into bytes: %w"
	failEncryptStructuredDocument   = "failed to encrypt structured document into JWE form: %w"
	failJWESerialize                = "failed to serialize JWE: %w"
	failDeserializeJWE              = "failed to deserialize JWE: %w"
	failDecryptJWE                  = "failed to decrypt JWE: %w"
	failUnmarshalStructuredDocument = "failed to unmarshal structured document: %w"
)

type marshalFunc func(interface{}) ([]byte, error)

// DocumentProcessor uses Aries crypto to encrypt and decrypt between
// Structured Documents and Encrypted Documents.
type DocumentProcessor struct {
	jweEncrypter jose.Encrypter
	jweDecrypter jose.Decrypter
	marshal      marshalFunc
}

// New returns a new instance of an DocumentProcessor.
func New(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter) *DocumentProcessor {
	return &DocumentProcessor{
		jweEncrypter: jweEncrypter,
		jweDecrypter: jweDecrypter,
		marshal:      json.Marshal,
	}
}

// Encrypt creates a new encrypted document based off of the given structured document.
func (a *DocumentProcessor) Encrypt(structuredDocument *edv.StructuredDocument) (*edv.EncryptedDocument, error) {
	structuredDocumentBytes, err := a.marshal(structuredDocument)
	if err != nil {
		return nil, fmt.Errorf(failMarshalStructuredDocument, err)
	}

	jwe, err := a.jweEncrypter.Encrypt(structuredDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf(failEncryptStructuredDocument, err)
	}

	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	if err != nil {
		return nil, fmt.Errorf(failJWESerialize, err)
	}

	encryptedDoc := edv.EncryptedDocument{
		ID:  structuredDocument.ID,
		JWE: []byte(serializedJWE),
	}

	return &encryptedDoc, nil
}

// Decrypt decrypts the encrypted document into a structured document.
func (a *DocumentProcessor) Decrypt(encryptedDocument *edv.EncryptedDocument) (*edv.StructuredDocument, error) {
	encryptedJWE, err := jose.Deserialize(string(encryptedDocument.JWE))
	if err != nil {
		return nil, fmt.Errorf(failDeserializeJWE, err)
	}

	structuredDocumentBytes, err := a.jweDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return nil, fmt.Errorf(failDecryptJWE, err)
	}

	var structuredDocument edv.StructuredDocument

	err = json.Unmarshal(structuredDocumentBytes, &structuredDocument)
	if err != nil {
		return nil, fmt.Errorf(failUnmarshalStructuredDocument, err)
	}

	return &structuredDocument, nil
}
