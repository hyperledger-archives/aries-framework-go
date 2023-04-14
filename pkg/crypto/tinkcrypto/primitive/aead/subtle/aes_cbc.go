/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

const (
	// AESCBCIVSize is the IV size that this implementation supports.
	AESCBCIVSize = subtle.AESCBCIVSize
)

// AESCBC is an implementation of AEAD interface.
type AESCBC = subtle.AESCBC

// NewAESCBC returns an AESCBC instance.
// The key argument should be the AES key, either 16, 24 or 32 bytes to select
// AES-128, AES-192 or AES-256.
func NewAESCBC(key []byte) (*AESCBC, error) {
	return subtle.NewAESCBC(key)
}
