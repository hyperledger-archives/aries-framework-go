/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"github.com/google/tink/go/tink"
)

// EncrypterHelper is a helper for Content Encryption of composite ECDH (ES/1PU) key wrapping + AEAD content encryption
// This interface is used internally by the composite primitives.
type EncrypterHelper interface {
	// GetSymmetricKeySize gives the size of the Encryption key (CEK) in bytes
	GetSymmetricKeySize() int

	// GetAEAD returns the newly created AEAD primitive used for the content Encryption
	GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error)

	// GetTagSize provides the aead primitive tag size
	GetTagSize() int

	// GetIVSize provides the aead primitive nonce size
	GetIVSize() int

	// BuildEncData will build the []byte representing the ciphertext sent to the end user as a result of the Composite
	// Encryption primitive execution
	BuildEncData(eAlg string, recipientsWK []*RecipientWrappedKey, ct, singleRecipientAAD []byte) ([]byte, error)

	// MergeSingleRecipientHeaders for single recipient encryption, recipient header info is available in the key, this
	// function will update AAD with this info and return the marshalled merged result
	MergeSingleRecipientHeaders(recipientWK *RecipientWrappedKey, aad []byte) ([]byte, error)

	// BuildDecData will build the []byte representing the ciphertext coming from encData struct returned as a result of
	// Composite Encrypt() call to prepare the Composite Decryption primitive execution
	BuildDecData(encData *EncryptedData) []byte
}
