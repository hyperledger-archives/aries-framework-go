/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
)

// ECDHAEADCompositeEncrypt is an instance of ECDH-ES encryption with Concat KDF
// and AEAD content encryption.
type ECDHAEADCompositeEncrypt struct {
	encHelper composite.EncrypterHelper
	cek       []byte
}

var _ api.CompositeEncrypt = (*ECDHAEADCompositeEncrypt)(nil)

// NewECDHAEADCompositeEncrypt returns ECDH (KW done outside of this Tink key implementation) AES encryption construct
// for AEAD content encryption.
func NewECDHAEADCompositeEncrypt(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeEncrypt {
	return &ECDHAEADCompositeEncrypt{
		encHelper: encHelper,
		cek:       cek,
	}
}

// Encrypt using composite ECDH with a Concat KDF key wrap and CBC+HMAC content encryption.
func (e *ECDHAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if e.cek == nil {
		return nil, fmt.Errorf("ecdhAEADCompositeEncrypt: missing cek")
	}

	aead, err := e.encHelper.GetAEAD(e.cek)
	if err != nil {
		return nil, err
	}

	ct, err := aead.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	return e.encHelper.BuildEncData(ct)
}
