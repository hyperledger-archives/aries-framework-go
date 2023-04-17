/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package subtle provides subtle implementations of the AEAD primitive.
package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

const (
	// AES128Size value in number of bytes.
	AES128Size = subtle.AES128Size
	// AES192Size value in number of bytes.
	AES192Size = subtle.AES192Size
	// AES256Size value in number of bytes.
	AES256Size = subtle.AES256Size
)

// ValidateAESKeySize checks if the given key size is a valid AES key size.
func ValidateAESKeySize(sizeInBytes uint32) error {
	return subtle.ValidateAESKeySize(sizeInBytes)
}

// ValidateAESKeySizeForGoJose checks if the given key size is a valid AES key size.
func ValidateAESKeySizeForGoJose(sizeInBytes uint32) error {
	return subtle.ValidateAESKeySizeForGoJose(sizeInBytes)
}
