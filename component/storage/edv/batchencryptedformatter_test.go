/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/component/storageutil/formattedstore"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestBatchEncrypter_FormatDeformat(t *testing.T) {
	tests := []struct {
		name          string
		perfCrypto    edv.PerfCrypto
		expectedError string
	}{
		{
			name: "test valid perf crypto formatting",
		},
		{
			name: "test invalid perf crypto formatting",
			perfCrypto: &testBadPerfCrypto{
				batchCryptoErr: fmt.Errorf("bad batch crypto"),
			},
			expectedError: "edv encryption failed to compute mac and encrypt: bad batch crypto",
		},
		{
			name: "test invalid perf crypto payload encoding",
			perfCrypto: &testBadPerfCrypto{
				batchCryptoVal: &edv.BatchCryptoPayload{
					DocPayload: "badBase64Payload!#",
				},
			},
			expectedError: "edv encryption can't decode document: illegal base64 data at input byte 16",
		},
		{
			name: "test invalid perf crypto payload encoding",
			perfCrypto: &testBadPerfCrypto{
				batchCryptoVal: &edv.BatchCryptoPayload{
					DocPayload: base64.RawURLEncoding.EncodeToString([]byte("payload")),
					DocID:      "badBase64DocID!#",
				},
			},
			expectedError: "edv encryption can't decode docID: illegal base64 data at input byte 14",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run("test valid perf crypto formatting", func(t *testing.T) {
			isValidPerf := tc.perfCrypto == nil
			formatter := createValidBatchEncryptedFormatter(t, isValidPerf, tc.perfCrypto,
				edv.WithDeterministicDocumentIDs())

			docID, protectedDoc, tags, err := formatter.Format("test-key", []byte("doc-payload"), spi.Tag{
				Name:  "tag1",
				Value: "tagValue1",
			}, spi.Tag{
				Name:  "tag2",
				Value: "tagValue2",
			})

			if isValidPerf {
				require.NoError(t, err)
				require.NotEmpty(t, docID)
				require.NotEmpty(t, protectedDoc)
				require.NotEmpty(t, tags)
			} else {
				require.EqualError(t, err, tc.expectedError)
				require.Empty(t, docID)
				require.Empty(t, protectedDoc)
				require.Empty(t, tags)
			}
		})
	}

	formatter := createValidBatchEncryptedFormatter(t, true, nil,
		edv.WithDeterministicDocumentIDs())

	provider := formattedstore.NewProvider(mem.NewProvider(), formatter)
	require.NotNil(t, provider)

	storagetest.TestAll(t, provider, storagetest.SkipSortTests(false))
}

func createValidBatchEncryptedFormatter(t *testing.T, isValidCrypto bool, perfCrypto edv.PerfCrypto,
	options ...edv.EncryptedFormatterOption) *edv.EncryptedFormatter {
	kmsSvc, cryptoSvc := createKMSAndCrypto(t)
	encrypter, decrypter, kid := createEncrypterAndDecrypter(t, kmsSvc, cryptoSvc)

	encKH, err := kmsSvc.Get(kid)
	require.NoError(t, err)

	_, macKH, err := kmsSvc.Create(kms.HMACSHA256Tag256Type)
	require.NoError(t, err)

	if isValidCrypto {
		perfCrypto = &testValidPerfCrypto{
			jweEncrypter: encrypter,
			jweDecrypter: decrypter,
			km:           kmsSvc,
			crypto:       cryptoSvc,
		}
	}

	ebc := edv.NewBatchCrypto(macKH, encKH, perfCrypto)

	formatter := edv.NewEncryptedFormatter(encrypter, decrypter, edv.NewMACCrypto(macKH, cryptoSvc),
		append(options, edv.WithEDVBatchCrypto(ebc))...)
	require.NotNil(t, formatter)

	return formatter
}

type testBadPerfCrypto struct {
	batchCryptoVal *edv.BatchCryptoPayload
	batchCryptoErr error
}

// BatchCrypto computes all the MACs and EDV encryptions necessary by a KMS/crypto instance. This is an invalid mock
// implementation.
func (e *testBadPerfCrypto) BatchCrypto(_ *edv.BatchCryptoPayload, _, _ interface{}) (*edv.BatchCryptoPayload, error) {
	return e.batchCryptoVal, e.batchCryptoErr
}

type testValidPerfCrypto struct {
	jweEncrypter *jose.JWEEncrypt
	jweDecrypter *jose.JWEDecrypt
	km           kms.KeyManager
	crypto       cryptoapi.Crypto
}

// BatchCrypto computes all the MACs and EDV encryptions necessary by a KMS/crypto instance. It is mocking server batch
// crypto operations locally. Encryption KH is not used in this implementation since it already uses the JWEEncrypter
// and JWEDecrypter that contain this KH pre loaded.
func (e *testValidPerfCrypto) BatchCrypto(req *edv.BatchCryptoPayload, macKH,
	_ interface{}) (*edv.BatchCryptoPayload, error) {
	if req == nil {
		return nil, fmt.Errorf("failed to ComputeCrypto: empty batch crypto request")
	}

	docID, err := e.generateDeterministicDocumentID(req.Prefix, req.DocID, macKH)
	if err != nil {
		return nil, err
	}

	docTags, err := e.formatTags(req.Prefix, req.DocTags, macKH)
	if err != nil {
		return nil, err
	}

	rawDoc, err := base64.RawURLEncoding.DecodeString(req.DocPayload)
	if err != nil {
		return nil, err
	}

	endDocument, err := e.formatValue(req.DocID, docID, rawDoc, req.DocTags, docTags)
	if err != nil {
		return nil, err
	}

	return &edv.BatchCryptoPayload{
		Prefix:     req.Prefix,
		DocID:      base64.RawURLEncoding.EncodeToString([]byte(docID)),
		DocTags:    docTags,
		DocPayload: base64.RawURLEncoding.EncodeToString(endDocument),
	}, nil
}

func (e *testValidPerfCrypto) generateDeterministicDocumentID(prefix, key string, macKH interface{}) (string, error) {
	if key == "" {
		return "", nil
	}

	keyHash, err := e.crypto.ComputeMAC([]byte(prefix+key), macKH)
	if err != nil {
		return "", fmt.Errorf(`failed to compute MAC based on key "%s": %w`, key, err)
	}

	return base58.Encode(keyHash[0:16]), nil
}

func (e *testValidPerfCrypto) formatTags(tagNamePrefix string, tags []spi.Tag, macKH interface{}) ([]spi.Tag, error) {
	formattedTags := make([]spi.Tag, len(tags))

	for i, tag := range tags {
		formattedTag, err := e.formatTag(tagNamePrefix, tag, macKH)
		if err != nil {
			return nil, fmt.Errorf("failed to format tag: %w", err)
		}

		formattedTags[i] = formattedTag
	}

	return formattedTags, nil
}

func (e *testValidPerfCrypto) formatTag(tagNamePrefix string, tag spi.Tag, macKH interface{}) (spi.Tag, error) {
	tagNameMAC, err := e.crypto.ComputeMAC([]byte(tagNamePrefix+tag.Name), macKH)
	if err != nil {
		return spi.Tag{}, fmt.Errorf(`failed to compute MAC for tag name "%s": %w`, tag.Name, err)
	}

	formattedTagName := base64.URLEncoding.EncodeToString(tagNameMAC)

	var formattedTagValue string

	if tag.Value != "" {
		tagValueMAC, err := e.crypto.ComputeMAC([]byte(tag.Value), macKH)
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

func (e *testValidPerfCrypto) formatValue(key, documentID string, value []byte,
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

func (e *testValidPerfCrypto) convertToIndexedAttributeCollection(
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

// structuredDocument represents a Structured Document for use with Aries. It's compatible with the model
// defined in https://identity.foundation/confidential-storage/#structureddocument.
type structuredDocument struct {
	ID      string                 `json:"id"`
	Meta    map[string]interface{} `json:"meta"`
	Content content                `json:"content"`
}

type content struct {
	UnformattedKey   string    `json:"unformattedKey"`
	UnformattedValue []byte    `json:"unformattedValue"`
	UnformattedTags  []spi.Tag `json:"unformattedTags"`
}

// indexedAttributeCollection represents a collection of indexed attributes,
// all of which share a common MAC algorithm and key.
// This format is based on https://identity.foundation/confidential-storage/#creating-encrypted-indexes.
type indexedAttributeCollection struct {
	Sequence          int                `json:"sequence"`
	HMAC              idTypePair         `json:"hmac"`
	IndexedAttributes []indexedAttribute `json:"attributes"`
}

// indexedAttribute represents a single indexed attribute.
type indexedAttribute struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Unique bool   `json:"unique"`
}

// idTypePair represents an ID+Type pair.
// TODO: #2262 This is a simplified version of the actual EDV query format, which is still not finalized
//  in the spec as of writing. See: https://github.com/decentralized-identity/confidential-storage/issues/34.
type idTypePair struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// encryptedDocument represents an Encrypted Document as defined in
// https://identity.foundation/confidential-storage/#encrypteddocument.
type encryptedDocument struct {
	ID                          string                       `json:"id"`
	Sequence                    int                          `json:"sequence"`
	IndexedAttributeCollections []indexedAttributeCollection `json:"indexed,omitempty"`
	JWE                         json.RawMessage              `json:"jwe"`
}
