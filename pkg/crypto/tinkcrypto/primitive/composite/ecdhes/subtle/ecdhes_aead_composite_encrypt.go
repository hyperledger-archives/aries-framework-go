/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/random"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
)

// ECDHESAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption
type ECDHESAEADCompositeEncrypt struct {
	recPublicKeys []*hybrid.ECPublicKey
	pointFormat   string
	encHelper     EncrypterHelper
}

var _ api.CompositeEncrypt = (*ECDHESAEADCompositeEncrypt)(nil)

// NewECDHESAEADCompositeEncrypt returns ECDH-ES encryption construct with Concat KDF key wrapping
// and AEAD content encryption
func NewECDHESAEADCompositeEncrypt(recipientsKeys []*hybrid.ECPublicKey, ptFormat string,
	encHelper EncrypterHelper) (*ECDHESAEADCompositeEncrypt, error) {
	var recipients []*hybrid.ECPublicKey

	for _, pub := range recipientsKeys {
		pubKey := &hybrid.ECPublicKey{
			Curve: pub.Curve,
			Point: hybrid.ECPoint{
				X: pub.Point.X,
				Y: pub.Point.Y,
			},
		}

		recipients = append(recipients, pubKey)
	}

	return &ECDHESAEADCompositeEncrypt{
		recPublicKeys: recipients,
		pointFormat:   ptFormat,
		encHelper:     encHelper,
	}, nil
}

// Encrypt using composite ECDH-ES with a Concat KDF key wrap and AEAD content encryption
func (e *ECDHESAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if len(e.recPublicKeys) == 0 {
		return nil, fmt.Errorf("ECDHESAEADCompositeEncrypt: missing recipients public keys for key wrapping")
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
		kek, err := senderKW.wrapKey(A256KWAlg, keySize)
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
		Ciphertext: ctAndTag[:tagOffset],
		IV:         iv,
		Tag:        ctAndTag[tagOffset:],
		Recipients: recipientsWK,
	}

	return json.Marshal(encData)
}
