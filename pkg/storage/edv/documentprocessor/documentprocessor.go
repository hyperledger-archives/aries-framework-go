/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package documentprocessor

import (
	"github.com/hyperledger/aries-framework-go/pkg/storage/edv"
)

// DocumentProcessor represents a type that can encrypt and decrypt between
// Structured Documents and Encrypted Documents.
type DocumentProcessor interface {
	Encrypt(*edv.StructuredDocument) (*edv.EncryptedDocument, error)
	Decrypt(*edv.EncryptedDocument) (*edv.StructuredDocument, error)
}
