/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/subtle/random"
	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/api"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// A256GCM is the default content encryption algorithm value as per
// the JWA specification: https://tools.ietf.org/html/rfc7518#section-5.1
const A256GCM = "A256GCM"

type marshalFunc func(interface{}) ([]byte, error)

// ECDHESAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption
type ECDHESAEADCompositeEncrypt struct {
	recPublicKeys []*PublicKey
	pointFormat   string
	encHelper     EncrypterHelper
	keyType       ecdhespb.KeyType
	marshalFunc   marshalFunc
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
		marshalFunc:   json.Marshal,
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
	cek := random.GetRandomBytes(uint32(keySize))

	var recipientsWK []*RecipientWrappedKey

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
			singleRecipientAAD, err = e.mergeSingleRecipientHeaders(kek, aad)
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

	return e.buildEncData(eAlg, recipientsWK, ct, singleRecipientAAD)
}

func (e *ECDHESAEADCompositeEncrypt) buildEncData(eAlg string, recipientsWK []*RecipientWrappedKey,
	ct, singleRecipientAAD []byte) ([]byte, error) {
	tagSize := e.encHelper.GetTagSize()
	ivSize := e.encHelper.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &EncryptedData{
		EncAlg:             eAlg,
		Ciphertext:         ctAndTag[:tagOffset],
		IV:                 iv,
		Tag:                ctAndTag[tagOffset:],
		Recipients:         recipientsWK,
		SingleRecipientAAD: singleRecipientAAD,
	}

	return e.marshalFunc(encData)
}

// for single recipient encryption, recipient header info is available in the key, update aad with this info
func (e *ECDHESAEADCompositeEncrypt) mergeSingleRecipientHeaders(recipientWK *RecipientWrappedKey,
	aad []byte) ([]byte, error) {
	newAAD, err := base64.RawURLEncoding.DecodeString(string(aad))
	if err != nil {
		return nil, err
	}

	rawHeaders := map[string]json.RawMessage{}

	err = json.Unmarshal(newAAD, &rawHeaders)
	if err != nil {
		return nil, err
	}

	kid, err := e.marshalFunc(recipientWK.KID)
	if err != nil {
		return nil, err
	}

	rawHeaders["kid"] = kid

	alg, err := e.marshalFunc(recipientWK.Alg)
	if err != nil {
		return nil, err
	}

	rawHeaders["alg"] = alg

	mEPK, err := convertRecKeyToMarshalledJWK(recipientWK)
	if err != nil {
		return nil, err
	}

	rawHeaders["epk"] = mEPK

	mAAD, err := e.marshalFunc(rawHeaders)
	if err != nil {
		return nil, err
	}

	return []byte(base64.RawURLEncoding.EncodeToString(mAAD)), nil
}

func convertRecKeyToMarshalledJWK(rec *RecipientWrappedKey) ([]byte, error) {
	var c elliptic.Curve

	c, err := hybrid.GetCurve(rec.EPK.Curve)
	if err != nil {
		return nil, err
	}

	recJWK := jose.JSONWebKey{
		KeyID: rec.KID,
		Use:   "enc",
		Key: &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(rec.EPK.X),
			Y:     new(big.Int).SetBytes(rec.EPK.Y),
		},
	}

	return recJWK.MarshalJSON()
}
