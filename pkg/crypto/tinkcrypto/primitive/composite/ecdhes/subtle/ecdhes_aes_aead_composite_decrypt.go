/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	hybrid "github.com/google/tink/go/hybrid/subtle"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

// package subtle provides the core crypto primitives to be used by ECDH-ES composite primitives. It is intended for
// internal use only.

// ECDHESAEADCompositeDecrypt is an instance of ECDH-ES decryption with Concat KDF
// and AEAD content decryption
type ECDHESAEADCompositeDecrypt struct {
	privateKey  *hybrid.ECPrivateKey
	pointFormat string
	encHelper   EncrypterHelper
	keyType     commonpb.KeyType
}

// NewECDHESAEADCompositeDecrypt returns ECDH-ES composite decryption construct with Concat KDF/ECDH-ES key unwrapping
// and AEAD payload decryption.
func NewECDHESAEADCompositeDecrypt(pvt *hybrid.ECPrivateKey, ptFormat string, encHelper EncrypterHelper,
	keyType commonpb.KeyType) *ECDHESAEADCompositeDecrypt {
	return &ECDHESAEADCompositeDecrypt{
		privateKey:  pvt,
		pointFormat: ptFormat,
		encHelper:   encHelper,
		keyType:     keyType,
	}
}

// Decrypt using composite ECDH-ES with a Concat KDF key unwrap and AEAD content decryption
func (d *ECDHESAEADCompositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	if d.privateKey == nil {
		return nil, fmt.Errorf("ECDHESAEADCompositeDecrypt: missing recipient private key for key unwrapping")
	}

	keySize := d.encHelper.GetSymmetricKeySize()

	var cek []byte

	encData := new(composite.EncryptedData)

	err := json.Unmarshal(ciphertext, encData)
	if err != nil {
		return nil, err
	}

	// TODO: add support for Chacha content encryption https://github.com/hyperledger/aries-framework-go/issues/1684
	switch d.keyType {
	case commonpb.KeyType_EC:
		if encData.EncAlg != A256GCM {
			return nil, fmt.Errorf("invalid content encryption algorihm '%s' for Decrypt()", encData.EncAlg)
		}
	default:
		return nil, fmt.Errorf("invalid key type '%s' for Decrypt()", d.keyType)
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
