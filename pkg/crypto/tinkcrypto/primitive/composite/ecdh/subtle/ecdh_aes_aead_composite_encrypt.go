/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
)

// ECDHAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption.
type ECDHAEADCompositeEncrypt = subtle.ECDHAEADCompositeEncrypt

// NewECDHAEADCompositeEncrypt returns ECDH (KW done outside of this Tink key implementation) AES encryption construct
// for AEAD content encryption.
func NewECDHAEADCompositeEncrypt(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeEncrypt {
	return subtle.NewECDHAEADCompositeEncrypt(encHelper, cek)
}
