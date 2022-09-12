/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
)

type cryptoSigner struct {
	cr ariescrypto.Crypto
	kh interface{}
}

func newCryptoSigner(cr ariescrypto.Crypto, keyHandle interface{}) *cryptoSigner {
	return &cryptoSigner{cr: cr, kh: keyHandle}
}

func (s *cryptoSigner) Sign(data []byte) ([]byte, error) {
	return s.cr.Sign(data, s.kh)
}

func (s *cryptoSigner) Alg() string {
	return ""
}
