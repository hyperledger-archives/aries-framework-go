/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

// EncryptedFormatter formats data for use with an Encrypted Data Vault.
type EncryptedFormatter struct {
	jweEncrypter jose.Encrypter
	jweDecrypter jose.Decrypter
	macCrypto    *MACCrypto
}

// NewEncryptedFormatter returns a new instance of an EncryptedFormatter.
func NewEncryptedFormatter(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter,
	macCrypto *MACCrypto) *EncryptedFormatter {
	return &EncryptedFormatter{
		jweEncrypter: jweEncrypter,
		jweDecrypter: jweDecrypter,
		macCrypto:    macCrypto,
	}
}

// Format turns key into an EDV-compatible document ID, turns tag names and values into the format needed for
// EDV encrypted indexes, and turns key + value + tags into an encrypted document, which is then returned as the
// formatted value from this function.
func (e *EncryptedFormatter) Format(key string, value []byte, tags ...spi.Tag) (string, []byte, []spi.Tag, error) {
	return e.format("", key, value, tags...)
}

// Deformat takes formattedValue (which is expected to be a marshalled encrypted document produced by the Format
// function above, and returns the unformatted key, value and tags which are all contained in formattedValue.
// The formatted key and formatted tags must come from the encrypted document (formattedValue) since they are
// hashed values, and therefore not reversible.
func (e *EncryptedFormatter) Deformat(_ string, formattedValue []byte, _ ...spi.Tag) (string, []byte,
	[]spi.Tag, error) {
	if formattedValue == nil {
		return "", nil, nil, errors.New("EDV encrypted formatter requires the formatted value " +
			"in order to return the deformatted key and tags")
	}

	structuredDocument, err := e.getStructuredDocFromEncryptedDoc(formattedValue)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get structured document from encrypted document bytes: %w", err)
	}

	return structuredDocument.Content.UnformattedKey, structuredDocument.Content.UnformattedValue,
		structuredDocument.Content.UnformattedTags, nil
}

func (e *EncryptedFormatter) format(keyAndTagPrefix, key string, value []byte, tags ...spi.Tag) (string, []byte,
	[]spi.Tag, error) {
	var formattedKey string

	if key != "" {
		var err error

		formattedKey, err = e.formatKey(keyAndTagPrefix + "-" + key)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to format key into an encrypted document ID: %w", err)
		}
	}

	formattedTags, err := e.formatTags(keyAndTagPrefix, tags)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to format tags: %w", err)
	}

	formattedValue, err := e.formatValue(key, formattedKey, value, tags, formattedTags)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to format value: %w", err)
	}

	return formattedKey, formattedValue, formattedTags, nil
}

func (e *EncryptedFormatter) getStructuredDocFromEncryptedDoc(
	encryptedDocBytes []byte) (structuredDocument, error) {
	var encryptedDocument encryptedDocument

	err := json.Unmarshal(encryptedDocBytes, &encryptedDocument)
	if err != nil {
		return structuredDocument{},
			fmt.Errorf("failed to unmarshal value into an encrypted document: %w", err)
	}

	encryptedJWE, err := jose.Deserialize(string(encryptedDocument.JWE))
	if err != nil {
		return structuredDocument{}, fmt.Errorf("failed to deserialize JWE: %w", err)
	}

	structuredDocumentBytes, err := e.jweDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return structuredDocument{}, fmt.Errorf("failed to decrypt JWE: %w", err)
	}

	var structuredDoc structuredDocument

	err = json.Unmarshal(structuredDocumentBytes, &structuredDoc)
	if err != nil {
		return structuredDocument{}, fmt.Errorf("failed to unmarshal structured document: %w", err)
	}

	return structuredDoc, nil
}

// TODO (#2376) Revisit how we're generating EDV document IDs, since it's technically not 100% in line with the spec.
//  (Spec requires randomly generated IDs)
// Generates an encrypted document ID based off of key.
func (e *EncryptedFormatter) formatKey(key string) (string, error) {
	keyHash, err := e.macCrypto.ComputeMAC([]byte(key))
	if err != nil {
		return "", fmt.Errorf(`failed to compute MAC based on key "%s": %w`, key, err)
	}

	return base58.Encode(keyHash[0:16]), nil
}

func (e *EncryptedFormatter) formatTags(tagPrefix string, tags []spi.Tag) ([]spi.Tag, error) {
	formattedTags := make([]spi.Tag, len(tags))

	for i, tag := range tags {
		tagNameMAC, err := e.macCrypto.ComputeMAC([]byte(tagPrefix + "-" + tag.Name))
		if err != nil {
			return nil, fmt.Errorf(`failed to compute MAC for tag name "%s": %w`, tag.Name, err)
		}

		formattedTagName := base64.URLEncoding.EncodeToString(tagNameMAC)

		var formattedTagValue string

		if tag.Value != "" {
			tagValueMAC, err := e.macCrypto.ComputeMAC([]byte(tag.Value))
			if err != nil {
				return nil, fmt.Errorf(`failed to compute MAC for tag value "%s": %w`, tag.Value, err)
			}

			formattedTagValue = base64.URLEncoding.EncodeToString(tagValueMAC)
		}

		// Since the formatted tag are hashes and can't be reversed, the only way we can retrieve
		// the unformatted tags later is to embed them in the stored value.
		formattedTags[i] = spi.Tag{
			Name:  formattedTagName,
			Value: formattedTagValue,
		}
	}

	return formattedTags, nil
}

func (e *EncryptedFormatter) formatValue(key, formattedKey string, value []byte,
	tags, formattedTags []spi.Tag) ([]byte, error) {
	var formattedValue []byte

	if value != nil {
		// Since the formatted key and tags are hashes and can't be reversed, the only way we can retrieve the
		// unformatted key and tags later is to embed them in the structured document.
		structuredDoc := createStructuredDocument(key, value, tags)

		structuredDocumentBytes, err := json.Marshal(structuredDoc)
		if err != nil {
			return nil, fmt.Errorf(`failed to marshal structured document into bytes: %w`, err)
		}

		jwe, err := e.jweEncrypter.Encrypt(structuredDocumentBytes)
		if err != nil {
			return nil, fmt.Errorf(`failed to encrypt structured document bytes: %w`, err)
		}

		serializedJWE, err := jwe.FullSerialize(json.Marshal)
		if err != nil {
			return nil, fmt.Errorf(`failed to serialize JWE: %w`, err)
		}

		indexedAttributeCollections := e.convertToIndexedAttributeCollection(formattedTags)

		encryptedDoc := encryptedDocument{
			ID:                          formattedKey,
			IndexedAttributeCollections: indexedAttributeCollections,
			JWE:                         []byte(serializedJWE),
		}

		encryptedDocumentBytes, err := json.Marshal(encryptedDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal encrypted document into bytes: %w", err)
		}

		formattedValue = encryptedDocumentBytes
	}

	return formattedValue, nil
}

func createStructuredDocument(key string, value []byte, tags []spi.Tag) structuredDocument {
	structuredDocumentContent := content{
		UnformattedKey:   key,
		UnformattedValue: value,
	}

	if len(tags) != 0 {
		structuredDocumentContent.UnformattedTags = tags
	}

	// In the spec, Structured Documents have IDs, but they don't really seem to serve
	// any purpose - at least not for us.
	// We will omit it for now. https://github.com/decentralized-identity/confidential-storage/issues/163
	return structuredDocument{
		Content: structuredDocumentContent,
	}
}

func (e *EncryptedFormatter) convertToIndexedAttributeCollection(
	formattedTags []spi.Tag) []indexedAttributeCollection {
	indexedAttributes := make([]indexedAttribute, len(formattedTags))

	for i, formattedTag := range formattedTags {
		indexedAttributes[i] = indexedAttribute{
			Name:  formattedTag.Name,
			Value: formattedTag.Value,
		}
	}

	indexedAttrCollection := indexedAttributeCollection{
		HMAC:              idTypePair{},
		IndexedAttributes: indexedAttributes,
	}

	return []indexedAttributeCollection{indexedAttrCollection}
}
