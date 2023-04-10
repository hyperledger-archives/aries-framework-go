/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package subtle provides subtle implementations of the AEAD primitive.
package subtle

import (
	"fmt"
)

const (
	maxInt = int(^uint(0) >> 1)
	// AES128Size value in number of bytes.
	AES128Size = 16
	// AES192Size value in number of bytes.
	AES192Size = 24
	// AES256Size value in number of bytes.
	AES256Size = 32
)

// ValidateAESKeySize checks if the given key size is a valid AES key size.
func ValidateAESKeySize(sizeInBytes uint32) error {
	switch sizeInBytes {
	case AES128Size, AES192Size, AES256Size:
		return nil
	default:
		return fmt.Errorf("invalid AES key size; want 16, 24 or 32, got %d", sizeInBytes)
	}
}

// ValidateAESKeySizeForGoJose checks if the given key size is a valid AES key size.
func ValidateAESKeySizeForGoJose(sizeInBytes uint32) error {
	const doubleKeySize = 2

	// double key size (hmac+cbc)
	switch sizeInBytes {
	case AES128Size * doubleKeySize, AES192Size * doubleKeySize, AES256Size * doubleKeySize:
		return nil
	default:
		return fmt.Errorf("invalid AES CBC key size; want 32, 48 or 64, got %d", sizeInBytes)
	}
}
