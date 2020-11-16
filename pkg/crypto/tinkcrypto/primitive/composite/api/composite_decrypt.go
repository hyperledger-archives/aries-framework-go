/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

// CompositeDecrypt will decrypt a `ciphertext` representing a composite encryption with a protected cek for the
// recipient caller of this interface. In order to get the plaintext embedded, this type is configured with the
// recipient key type that will decrypt the embedded cek first.
type CompositeDecrypt interface {
	// Decrypt operation: decrypts ciphertext representing a serialized EncryptedData (mainly extracted from a
	// JWE message) for a given recipient. It uses an unwrapped cek and the AEAD decrypt primitive.
	// returns resulting plaintext extracted from the serialized object.
	Decrypt(cipherText, additionalData []byte) ([]byte, error)
}
