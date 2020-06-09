/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/aes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	josecipher "github.com/square/go-jose/v3/cipher"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
)

// ECDH1PUConcatKDFRecipientKW represents concat KDF based ECDH-1PU (One-Pass Unified Model) KW (key wrapping)
// for ECDH-1PU recipient's unwrapping of CEK
type ECDH1PUConcatKDFRecipientKW struct {
	recipientPrivateKey *hybrid.ECPrivateKey
}

// unwrapKey will do ECDH-1PU key unwrapping
func (s *ECDH1PUConcatKDFRecipientKW) unwrapKey(recWK *composite.RecipientWrappedKey, keySize int) ([]byte, error) {
	if recWK == nil {
		return nil, fmt.Errorf("unwrapKey: RecipientWrappedKey is empty")
	}

	// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637

	recPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: s.recipientPrivateKey.PublicKey.Curve,
			X:     s.recipientPrivateKey.PublicKey.Point.X,
			Y:     s.recipientPrivateKey.PublicKey.Point.Y,
		},
		D: s.recipientPrivateKey.D,
	}

	epkCurve, err := hybrid.GetCurve(recWK.EPK.Curve)
	if err != nil {
		return nil, err
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(recWK.EPK.X),
		Y:     new(big.Int).SetBytes(recWK.EPK.Y),
	}

	// TODO replace below calls with new 1PU key derivation algorithm
	// DeriveECDHES checks if keys are on the same curve
	kek := josecipher.DeriveECDHES(recWK.Alg, []byte{}, []byte{}, recPrivKey, epkPubKey, keySize)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	return josecipher.KeyUnwrap(block, recWK.EncryptedCEK)
}
