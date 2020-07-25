/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"fmt"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

// A256GCM is the default content encryption algorithm value as per
// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
const A256GCM = "A256GCM"

// ECDH1PUAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption.
type ECDH1PUAEADCompositeEncrypt struct {
	senderPrivKey *hybrid.ECPrivateKey
	recPublicKeys []*composite.PublicKey
	pointFormat   string
	encHelper     composite.EncrypterHelper
	keyType       commonpb.KeyType
}

var _ api.CompositeEncrypt = (*ECDH1PUAEADCompositeEncrypt)(nil)

// NewECDH1PUAEADCompositeEncrypt returns ECDH-ES encryption construct with Concat KDF key wrapping
// and AEAD content encryption.
func NewECDH1PUAEADCompositeEncrypt(recipientsKeys []*composite.PublicKey, senderPrivKey *hybrid.ECPrivateKey,
	ptFormat string, encHelper composite.EncrypterHelper, keyType commonpb.KeyType) *ECDH1PUAEADCompositeEncrypt {
	return &ECDH1PUAEADCompositeEncrypt{
		senderPrivKey: senderPrivKey,
		recPublicKeys: recipientsKeys,
		pointFormat:   ptFormat,
		encHelper:     encHelper,
		keyType:       keyType,
	}
}

// Encrypt using composite ECDH-1PU with a 1PU KDF key wrap and AEAD content encryption.
func (e *ECDH1PUAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if len(e.recPublicKeys) == 0 {
		return nil, fmt.Errorf("ECDH1PUAEADCompositeEncrypt: missing recipients public keys for key wrapping")
	}

	var eAlg, kwAlg string

	// TODO add chacha alg support too, https://github.com/hyperledger/aries-framework-go/issues/1684
	switch e.keyType {
	case commonpb.KeyType_EC:
		eAlg = A256GCM
		kwAlg = A256KWAlg
	default:
		return nil, fmt.Errorf("ECDH1PUAEADCompositeEncrypt: bad key type: '%s'", e.keyType)
	}

	keySize := e.encHelper.GetSymmetricKeySize()
	cek := random.GetRandomBytes(uint32(keySize))

	var recipientsWK []*composite.RecipientWrappedKey

	var singleRecipientAAD []byte

	for _, rec := range e.recPublicKeys {
		senderKW := &ECDH1PUConcatKDFSenderKW{
			senderPrivateKey:   e.senderPrivKey,
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

	return e.encHelper.BuildEncData(eAlg, recipientsWK, ct, singleRecipientAAD)
}
