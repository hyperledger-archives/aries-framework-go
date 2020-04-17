/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/subtle/hybrid"
)

// ECDHESAEADCompositeDecrypt is an instance of ECDH-ES decryption with Concat KDF
// and AEAD content decryption
type ECDHESAEADCompositeDecrypt struct {
	privateKey  *hybrid.ECPrivateKey
	pointFormat string
	encHelper   EncrypterHelper
}

// NewECDHESAEADCompositeDecrypt returns ECDH-ES composite decryption construct with Concat KDF/ECDH-ES key unwrapping
// and AEAD payload decryption.
func NewECDHESAEADCompositeDecrypt(pvt *hybrid.ECPrivateKey, ptFormat string,
	encHelper EncrypterHelper) (*ECDHESAEADCompositeDecrypt, error) {
	return &ECDHESAEADCompositeDecrypt{
		privateKey:  pvt,
		pointFormat: ptFormat,
		encHelper:   encHelper,
	}, nil
}

// Decrypt using composite ECDH-ES with a Concat KDF key unwrap and AEAD content decryption
func (d *ECDHESAEADCompositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	if d.privateKey == nil {
		return nil, fmt.Errorf("ECDHESAEADCompositeDecrypt: missing recipient private key for key unwrapping")
	}

	keySize := d.encHelper.GetSymmetricKeySize()

	var cek []byte

	encData := new(EncryptedData)

	err := json.Unmarshal(ciphertext, encData)
	if err != nil {
		return nil, err
	}

	for _, rec := range encData.Recipients {
		recipientKW := &ECDHESConcatKDFRecipientKW{
			recipientPrivateKey: d.privateKey,
		}

		// TODO: add support for 25519 key unwrapping https://github.com/hyperledger/aries-framework-go/issues/1637
		cek, err = recipientKW.unwrapKey(rec, keySize)
		if err == nil {
			break
		}
	}

	if cek == nil {
		return nil, fmt.Errorf("ecdh-es decrypt: cek unwrap failed for all recipients keys")
	}

	aead, err := d.encHelper.GetAEAD(cek)
	if err != nil {
		return nil, err
	}

	iv := encData.IV
	tag := encData.Tag
	ct := encData.Ciphertext
	finalCT := append(iv, ct...)
	finalCT = append(finalCT, tag...)

	return aead.Decrypt(finalCT, aad)
}
