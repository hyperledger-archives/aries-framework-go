/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"

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
	// TODO return correct alg
	return ""
}

type secp256k1Signer struct {
	privKey *ecdsa.PrivateKey
}

func newSecp256k1Signer(privKey *ecdsa.PrivateKey) *secp256k1Signer {
	return &secp256k1Signer{
		privKey: privKey,
	}
}

//nolint:gomnd
func (signer *secp256k1Signer) Sign(payload []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, signer.privKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := signer.privKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func (signer *secp256k1Signer) Alg() string {
	return "ES256K"
}
