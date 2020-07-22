/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/aes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	josecipher "github.com/square/go-jose/v3/cipher"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
)

// ECDH1PUConcatKDFRecipientKW represents concat KDF based ECDH-1PU (One-Pass Unified Model) KW (key wrapping)
// for ECDH-1PU recipient's unwrapping of CEK.
type ECDH1PUConcatKDFRecipientKW struct {
	senderPubKey        *hybrid.ECPublicKey
	recipientPrivateKey *hybrid.ECPrivateKey
}

// unwrapKey will do ECDH-1PU key unwrapping.
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

	if s.senderPubKey.Curve != s.recipientPrivateKey.PublicKey.Curve || s.senderPubKey.Curve != epkCurve {
		return nil, errors.New("unwrapKey: recipient and sender keys are not on the same curve")
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(recWK.EPK.X),
		Y:     new(big.Int).SetBytes(recWK.EPK.Y),
	}

	senderPubKey := &ecdsa.PublicKey{
		Curve: s.senderPubKey.Curve,
		X:     s.senderPubKey.Point.X,
		Y:     s.senderPubKey.Point.Y,
	}

	kek, err := deriveRecipient1Pu(recWK.Alg, epkPubKey, senderPubKey, recPrivKey, keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	return josecipher.KeyUnwrap(block, recWK.EncryptedCEK)
}

func deriveRecipient1Pu(kwAlg string, ephemeralPub, senderPubKey *ecdsa.PublicKey, recPrivKey *ecdsa.PrivateKey,
	keySize int) ([]byte, error) {
	// DeriveECDHES checks if keys are on the same curve
	ze := josecipher.DeriveECDHES(kwAlg, []byte{}, []byte{}, recPrivKey, ephemeralPub, keySize)
	zs := josecipher.DeriveECDHES(kwAlg, []byte{}, []byte{}, recPrivKey, senderPubKey, keySize)

	return derive1Pu(kwAlg, ze, zs, keySize)
}
