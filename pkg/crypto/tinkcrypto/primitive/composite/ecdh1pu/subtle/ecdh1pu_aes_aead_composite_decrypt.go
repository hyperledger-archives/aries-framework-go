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

// package subtle provides the core crypto primitives to be used by ECDH-1PU composite primitives. It is intended for
// internal use only.

// ECDH1PUAEADCompositeDecrypt is an instance of ECDH-1PU decryption with Concat KDF
// and AEAD content decryption.
type ECDH1PUAEADCompositeDecrypt struct {
	senderPubKey *hybrid.ECPublicKey
	recPrivKey   *hybrid.ECPrivateKey
	pointFormat  string
	encHelper    composite.EncrypterHelper
	keyType      commonpb.KeyType
}

// NewECDH1PUAEADCompositeDecrypt returns ECDH-ES composite decryption construct with Concat KDF/ECDH-1PU key unwrapping
// and AEAD payload decryption.
func NewECDH1PUAEADCompositeDecrypt(senderPub *hybrid.ECPublicKey, recPvt *hybrid.ECPrivateKey, ptFormat string,
	encHelper composite.EncrypterHelper, keyType commonpb.KeyType) *ECDH1PUAEADCompositeDecrypt {
	return &ECDH1PUAEADCompositeDecrypt{
		senderPubKey: senderPub,
		recPrivKey:   recPvt,
		pointFormat:  ptFormat,
		encHelper:    encHelper,
		keyType:      keyType,
	}
}

// Decrypt using composite ECDH-ES with a Concat KDF key unwrap and AEAD content decryption.
func (d *ECDH1PUAEADCompositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	if d.recPrivKey == nil {
		return nil, fmt.Errorf("ECDH1PUAEADCompositeDecrypt: missing recipient private key for key unwrapping")
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
		recipientKW := &ECDH1PUConcatKDFRecipientKW{
			senderPubKey:        d.senderPubKey,
			recipientPrivateKey: d.recPrivKey,
		}

		// TODO: add support for 25519 key unwrapping https://github.com/hyperledger/aries-framework-go/issues/1637
		cek, err = recipientKW.unwrapKey(rec, keySize)
		if err == nil {
			break
		}
	}

	if cek == nil {
		return nil, fmt.Errorf("ecdh-1pu decrypt: cek unwrap failed for all recipients keys")
	}

	aead, err := d.encHelper.GetAEAD(cek)
	if err != nil {
		return nil, err
	}

	finalCT := d.encHelper.BuildDecData(encData)

	return aead.Decrypt(finalCT, aad)
}
