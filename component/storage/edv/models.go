/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"

	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

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

// encryptedDocument represents an Encrypted Document as defined in
// https://identity.foundation/confidential-storage/#encrypteddocument.
type encryptedDocument struct {
	ID                          string                       `json:"id"`
	Sequence                    int                          `json:"sequence"`
	IndexedAttributeCollections []indexedAttributeCollection `json:"indexed,omitempty"`
	JWE                         json.RawMessage              `json:"jwe"`
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
type idTypePair struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// nameAndValueQuery represents a name+value pair that can be used to query the encrypted indices for specific data.
// TODO: #2262 This is a simplified version of the actual EDV query format, which is still not finalized
//  in the spec as of writing. See: https://github.com/decentralized-identity/confidential-storage/issues/34.
type nameAndValueQuery struct {
	ReturnFullDocuments bool   `json:"returnFullDocuments"`
	Name                string `json:"index"`
	Value               string `json:"equals"`
}

// hasQuery represents a simpler version of query above that matches all documents that are tagged with the index name
// specified in "has", regardless of index value.
type hasQuery struct {
	ReturnFullDocuments bool   `json:"returnFullDocuments"`
	Has                 string `json:"has"`
}

const (
	// upsertDocumentVaultOperation represents an upsert operation to be performed in a batch.
	upsertDocumentVaultOperation = "upsert"
	// deleteDocumentVaultOperation represents a delete operation to be performed in a batch.
	deleteDocumentVaultOperation = "delete"
)

// vaultOperation represents an upsert or delete operation to be performed in a vault.
type vaultOperation struct {
	Operation         string          `json:"operation"`          // Valid values: upsert,delete
	DocumentID        string          `json:"id,omitempty"`       // Only used if Operation=delete
	EncryptedDocument json.RawMessage `json:"document,omitempty"` // Only used if Operation=upsert
}

// indexOperation represents an operation to add, update or remove indexes.
type indexOperation struct {
	Operation      string   `json:"operation"`
	AttributeNames []string `json:"attributeNames"`
}
