/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
)

// package subtle provides the core crypto primitives to be used by ECDH composite primitives. It is intended for
// internal use only.

// ECDHAEADCompositeDecrypt is an instance of AES-GCM decryption in the context of ECDH/concat kdf WK of CEK
// and AEAD content decryption.
type ECDHAEADCompositeDecrypt struct {
	encHelper composite.EncrypterHelper
	cek       []byte
}

// NewECDHAEADCompositeDecrypt returns ECDH composite decryption construct with Concat KDF/ECDH-ES key unwrapping
// and AEAD payload decryption.
func NewECDHAEADCompositeDecrypt(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeDecrypt {
	return &ECDHAEADCompositeDecrypt{
		encHelper: encHelper,
		cek:       cek,
	}
}

// Decrypt using composite ECDH-ES with a Concat KDF key unwrap and AEAD content decryption.
func (d *ECDHAEADCompositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	encData := new(composite.EncryptedData)

	err := json.Unmarshal(ciphertext, encData)
	if err != nil {
		return nil, err
	}

	if d.cek == nil {
		return nil, fmt.Errorf("ecdh decrypt: missing cek")
	}

	aead, err := d.encHelper.GetAEAD(d.cek)
	if err != nil {
		return nil, err
	}

	finalCT := d.encHelper.BuildDecData(encData)

	return aead.Decrypt(finalCT, aad)
}
