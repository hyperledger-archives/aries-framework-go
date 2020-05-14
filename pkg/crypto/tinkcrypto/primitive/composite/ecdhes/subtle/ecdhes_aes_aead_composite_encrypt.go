/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// A256GCM is the default content encryption algorithm value as per
// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
const A256GCM = "A256GCM"

// ECDHESAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption
type ECDHESAEADCompositeEncrypt struct {
	recPublicKeys []*PublicKey
	pointFormat   string
	encHelper     EncrypterHelper
	keyType       ecdhespb.KeyType
}

var _ api.CompositeEncrypt = (*ECDHESAEADCompositeEncrypt)(nil)

// NewECDHESAEADCompositeEncrypt returns ECDH-ES encryption construct with Concat KDF key wrapping
// and AEAD content encryption
func NewECDHESAEADCompositeEncrypt(recipientsKeys []*PublicKey, ptFormat string,
	encHelper EncrypterHelper, keyType ecdhespb.KeyType) *ECDHESAEADCompositeEncrypt {
	return &ECDHESAEADCompositeEncrypt{
		recPublicKeys: recipientsKeys,
		pointFormat:   ptFormat,
		encHelper:     encHelper,
		keyType:       keyType,
	}
}

// Encrypt using composite ECDH-ES with a Concat KDF key wrap and AEAD content encryption
func (e *ECDHESAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if len(e.recPublicKeys) == 0 {
		return nil, fmt.Errorf("ECDHESAEADCompositeEncrypt: missing recipients public keys for key wrapping")
	}

	var eAlg, kwAlg string

	// TODO add chacha alg support too, https://github.com/hyperledger/aries-framework-go/issues/1684
	switch e.keyType {
	case ecdhespb.KeyType_EC:
		eAlg = A256GCM
		kwAlg = A256KWAlg
	default:
		return nil, fmt.Errorf("ECDHESAEADCompositeEncrypt: bad key type: '%s'", e.keyType)
	}

	keySize := e.encHelper.GetSymmetricKeySize()
	tagSize := e.encHelper.GetTagSize()
	ivSize := e.encHelper.GetIVSize()
	cek := random.GetRandomBytes(uint32(keySize))

	var recipientsWK []*RecipientWrappedKey

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
	}

	aead, err := e.encHelper.GetAEAD(cek)
	if err != nil {
		return nil, err
	}

	ct, err := aead.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &EncryptedData{
		EncAlg:     eAlg,
		Ciphertext: ctAndTag[:tagOffset],
		IV:         iv,
		Tag:        ctAndTag[tagOffset:],
		Recipients: recipientsWK,
	}

	return json.Marshal(encData)
}
