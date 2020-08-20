/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"fmt"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

// ECDHESAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption.
type ECDHESAEADCompositeEncrypt struct {
	recPublicKeys []*composite.PublicKey
	pointFormat   string
	encHelper     composite.EncrypterHelper
	keyType       commonpb.KeyType
}

var _ api.CompositeEncrypt = (*ECDHESAEADCompositeEncrypt)(nil)

// NewECDHESAEADCompositeEncrypt returns ECDH-ES encryption construct with Concat KDF key wrapping
// and AEAD content encryption.
func NewECDHESAEADCompositeEncrypt(recipientsKeys []*composite.PublicKey, ptFormat string,
	encHelper composite.EncrypterHelper, keyType commonpb.KeyType) *ECDHESAEADCompositeEncrypt {
	return &ECDHESAEADCompositeEncrypt{
		recPublicKeys: recipientsKeys,
		pointFormat:   ptFormat,
		encHelper:     encHelper,
		keyType:       keyType,
	}
}

// Encrypt using composite ECDH-ES with a Concat KDF key wrap and AEAD content encryption.
func (e *ECDHESAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if len(e.recPublicKeys) == 0 {
		return nil, fmt.Errorf("ECDHESAEADCompositeEncrypt: missing recipients public keys for key wrapping")
	}

	var eAlg, eTyp, kwAlg string

	// TODO add chacha alg support too, https://github.com/hyperledger/aries-framework-go/issues/1684
	switch e.keyType {
	case commonpb.KeyType_EC:
		eAlg = composite.A256GCM
		kwAlg = A256KWAlg
	default:
		return nil, fmt.Errorf("ECDHESAEADCompositeEncrypt: bad key type: '%s'", e.keyType)
	}

	eTyp = composite.DIDCommEncType

	keySize := e.encHelper.GetSymmetricKeySize()
	cek := random.GetRandomBytes(uint32(keySize))

	var recipientsWK []*composite.RecipientWrappedKey

	var singleRecipientAAD []byte

	for _, rec := range e.recPublicKeys {
		senderKW := &ECDHESConcatKDFSenderKW{
			recipientPublicKey: rec,
			cek:                cek,
		}

		// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637
		kek, err := senderKW.wrapKey(kwAlg, keySize)
		if err != nil {
			return nil, err
		}

		recipientsWK = append(recipientsWK, kek)

		if len(e.recPublicKeys) == 1 {
			singleRecipientAAD, err = e.encHelper.MergeSingleRecipientHeaders(kek, aad)
			if err != nil {
				return nil, err
			}

			aad = singleRecipientAAD
		}
	}

	aead, err := e.encHelper.GetAEAD(cek)
	if err != nil {
		return nil, err
	}

	ct, err := aead.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	return e.encHelper.BuildEncData(eAlg, eTyp, recipientsWK, ct, singleRecipientAAD)
}
