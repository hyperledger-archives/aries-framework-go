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
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const edvIDSize = 16

// EncryptedFormatterOption allows for configuration of an EncryptedFormatter.
type EncryptedFormatterOption func(opts *EncryptedFormatter)

// WithDeterministicDocumentIDs indicates whether the document IDs produced by this formatter can be
// deterministically derived (using an HMAC function) from the unformatted keys. Having deterministic document IDs
// allows the EDV REST storage provider (and the more general formatted storage provider wrapper in the
// storageutil module) to operate faster. Per the Confidential Storage specification, document IDs are supposed
// to be randomly generated. Other than the randomness aspect, the document IDs produced by this formatter with
// this optimization enabled are still in the correct format: Base58-encoded 128-bit values. This means that they
// should still be valid in any EDV server, since it's impossible for any EDV server to determine whether our IDs
// are random anyway.
func WithDeterministicDocumentIDs() EncryptedFormatterOption {
	return func(encryptedFormatter *EncryptedFormatter) {
		encryptedFormatter.useDeterministicDocumentIDs = true
	}
}

// WithEDVBatchCrypto adds support for executing MAC/JWE encryption and KeyWrapping in 1 batch call on a remote KMS
// server. If set, then the default Encryption and MACCrypto calls during format() will not be executed locally.
// BatchCrypto handles these operations instead.
func WithEDVBatchCrypto(batchCrypto *BatchCrypto) EncryptedFormatterOption {
	return func(encryptedFormatter *EncryptedFormatter) {
		encryptedFormatter.edvBatchCrypto = batchCrypto
	}
}

// EncryptedFormatter formats data for use with an Encrypted Data Vault.
type EncryptedFormatter struct {
	jweEncrypter                jose.Encrypter
	jweDecrypter                jose.Decrypter
	macCrypto                   *MACCrypto
	edvBatchCrypto              *BatchCrypto
	useDeterministicDocumentIDs bool
}

// NewEncryptedFormatter returns a new instance of an EncryptedFormatter.
func NewEncryptedFormatter(jweEncrypter jose.Encrypter, jweDecrypter jose.Decrypter, macCrypto *MACCrypto,
	options ...EncryptedFormatterOption) *EncryptedFormatter {
	encryptedFormatter := &EncryptedFormatter{
		jweEncrypter: jweEncrypter,
		jweDecrypter: jweDecrypter,
		macCrypto:    macCrypto,
	}

	for _, option := range options {
		option(encryptedFormatter)
	}

	return encryptedFormatter
}

// Format returns formatted versions of key, value and tags in the following ways:
// For the formatted key (string): If this EncryptedFormatter was initialized with the WithDeterministicDocumentIDs
// option, then the formatted key (document ID) will be generated in a deterministic way that allows it to be
// derived from the unformatted key. Otherwise, the document ID is generated in a random manner.
// For the formatted value ([]byte): This will be a marshalled EDV encrypted document based on the
// unformatted key, value and tags.
// For the formatted tags ([]spi.Tag): The tag names and values are converted to the same format that EDV encrypted
// indexes use.
// and tags turns key into an EDV-compatible document ID, turns tag names and values into the format needed for
// EDV encrypted indexes, and turns key + value + tags into an encrypted document, which is then returned as the
// formatted value from this function.
func (e *EncryptedFormatter) Format(key string, value []byte, tags ...spi.Tag) (string, []byte, []spi.Tag, error) {
	if e.edvBatchCrypto != nil {
		return e.batchFormat("", key, value, tags...)
	}

	return e.format("", key, value, tags...)
}

// Deformat takes formattedValue (which is expected to be a marshalled encrypted document produced by the Format
// function above), and returns the unformatted key, value and tags which are all contained in formattedValue.
// The unformatted key and tags must come from the encrypted document (formatted value) since they cannot be
// cannot be derived from the formatted key and tags, respectively.
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

// UsesDeterministicKeyFormatting indicates whether this encrypted formatter will produce deterministic or random
// document IDs. See the WithDeterministicDocumentIDs option near the top of this file for more information.
func (e *EncryptedFormatter) UsesDeterministicKeyFormatting() bool {
	return e.useDeterministicDocumentIDs
}

func (e *EncryptedFormatter) format(keyAndTagPrefix, key string, value []byte, tags ...spi.Tag) (string, []byte,
	[]spi.Tag, error) {
	var documentID string

	var err error

	if e.useDeterministicDocumentIDs {
		documentID, err = e.generateDeterministicDocumentID(keyAndTagPrefix, key)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to format key into an encrypted document ID: %w", err)
		}
	} else {
		documentID, err = generateRandomDocumentID()
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to generate EDV-compatible ID: %w", err)
		}
	}

	formattedTags, err := e.formatTags(keyAndTagPrefix, tags)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to format tags: %w", err)
	}

	var formattedValue []byte

	if documentID != "" {
		// Since the formatted tag are hashes and can't be reversed, the only way we can retrieve
		// the unformatted tags later is to embed them in the stored value.
		formattedValue, err = e.formatValue(key, documentID, value, tags, formattedTags)
		if err != nil {
			return "", nil, nil, fmt.Errorf("failed to format value: %w", err)
		}
	}

	return documentID, formattedValue, formattedTags, nil
}

func (e *EncryptedFormatter) batchFormat(tagNamePrefix, key string, value []byte, tags ...spi.Tag) (string,
	[]byte, []spi.Tag, error) {
	edvReq := &BatchCryptoPayload{
		DocID:      tagNamePrefix + key,
		DocTags:    tags,
		DocPayload: base64.RawURLEncoding.EncodeToString(value),
	}

	edvRes, err := e.edvBatchCrypto.ComputeCrypto(edvReq)
	if err != nil {
		return "", nil, nil, fmt.Errorf("edv encryption failed to compute mac and encrypt: %w", err)
	}

	formattedValue, err := base64.RawURLEncoding.DecodeString(edvRes.DocPayload)
	if err != nil {
		return "", nil, nil, fmt.Errorf("edv encryption can't decode document: %w", err)
	}

	docID, err := base64.RawURLEncoding.DecodeString(edvRes.DocID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("edv encryption can't decode docID: %w", err)
	}

	if len(docID) >= edvIDSize {
		return base58.Encode(docID[0:edvIDSize]), formattedValue, tags, nil
	}

	return string(docID), formattedValue, tags, nil
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

// Generates an encrypted document ID based off of key.
func (e *EncryptedFormatter) generateDeterministicDocumentID(prefix, key string) (string, error) {
	if key == "" {
		return "", nil
	}

	keyHash, err := e.macCrypto.ComputeMAC([]byte(prefix + key))
	if err != nil {
		return "", fmt.Errorf(`failed to compute MAC based on key "%s": %w`, key, err)
	}

	return base58.Encode(keyHash[0:edvIDSize]), nil
}

func generateRandomDocumentID() (string, error) {
	randomBytes := make([]byte, edvIDSize)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base58.Encode(randomBytes), nil
}

func (e *EncryptedFormatter) formatTags(tagNamePrefix string, tags []spi.Tag) ([]spi.Tag, error) {
	formattedTags := make([]spi.Tag, len(tags))

	for i, tag := range tags {
		formattedTag, err := e.formatTag(tagNamePrefix, tag)
		if err != nil {
			return nil, fmt.Errorf("failed to format tag: %w", err)
		}

		formattedTags[i] = formattedTag
	}

	return formattedTags, nil
}

func (e *EncryptedFormatter) formatTag(tagNamePrefix string, tag spi.Tag) (spi.Tag, error) {
	tagNameMAC, err := e.macCrypto.ComputeMAC([]byte(tagNamePrefix + tag.Name))
	if err != nil {
		return spi.Tag{}, fmt.Errorf(`failed to compute MAC for tag name "%s": %w`, tag.Name, err)
	}

	formattedTagName := base64.URLEncoding.EncodeToString(tagNameMAC)

	var formattedTagValue string

	if tag.Value != "" {
		tagValueMAC, err := e.macCrypto.ComputeMAC([]byte(tag.Value))
		if err != nil {
			return spi.Tag{}, fmt.Errorf(`failed to compute MAC for tag value "%s": %w`, tag.Value, err)
		}

		formattedTagValue = base64.URLEncoding.EncodeToString(tagValueMAC)
	}

	return spi.Tag{
		Name:  formattedTagName,
		Value: formattedTagValue,
	}, nil
}

func (e *EncryptedFormatter) formatValue(key, documentID string, value []byte,
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
			ID:                          documentID,
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
