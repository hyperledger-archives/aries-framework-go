/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

// AESCBCHMAC is an implementation of AEAD interface.
type AESCBCHMAC = subtle.AESCBCHMAC

// NewAESCBCHMAC returns an AES CBC HMAC instance.
// The key argument should be the AES key, either 16, 24 or 32 bytes to select AES-128, AES-192 or AES-256.
// ivSize specifies the size of the IV in bytes.
func NewAESCBCHMAC(key []byte) (*AESCBCHMAC, error) {
	return subtle.NewAESCBCHMAC(key)
}
