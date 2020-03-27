/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonwebsignature2020

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// PublicKeyVerifierP256 verifies a ECDSA signature taking public key bytes as input.
// NOTE: this verifier is present for backward compatibility reasons and can be removed soon.
// Please use CryptoVerifier or your own verifier.
type PublicKeyVerifierP256 struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifierP256) Verify(pubKey *sigverifier.PublicKey, doc, signature []byte) error {
	pubKeyBytes := pubKey.Value

	// TODO Read curve parameter from PublicKey, support P384 and P521 curves
	//   (https://github.com/hyperledger/aries-framework-go/issues/1527)
	curve := elliptic.P256()

	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	if x == nil {
		return errors.New("ecdsa: invalid public key")
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	p256KeySize := 32
	if len(signature) != 2*p256KeySize {
		return errors.New("ecdsa: invalid signature size")
	}

	hasher := crypto.SHA256.New()

	_, err := hasher.Write(doc)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:p256KeySize])
	s := big.NewInt(0).SetBytes(signature[p256KeySize:])

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}
