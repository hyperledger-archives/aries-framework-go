/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
)

// package subtle provides the core crypto primitives to be used by ECDH composite primitives. It is intended for
// internal use only.

// ECDHAEADCompositeDecrypt is an instance of AES-GCM decryption in the context of ECDH/concat kdf WK of CEK
// and AEAD content decryption.
type ECDHAEADCompositeDecrypt = subtle.ECDHAEADCompositeDecrypt

// NewECDHAEADCompositeDecrypt returns ECDH composite decryption construct with Concat KDF/ECDH-ES key unwrapping
// and AEAD payload decryption.
func NewECDHAEADCompositeDecrypt(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeDecrypt {
	return subtle.NewECDHAEADCompositeDecrypt(encHelper, cek)
}
