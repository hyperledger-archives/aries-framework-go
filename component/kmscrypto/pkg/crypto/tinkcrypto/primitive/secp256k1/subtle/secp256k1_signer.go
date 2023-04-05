/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/google/tink/go/subtle"
)

// Secp256K1Signer is an implementation of Signer for secp256k1 Secp256k2 (Koblitz curve).
// At the moment, the implementation only accepts DER encoding.
type Secp256K1Signer struct {
	privateKey *ecdsa.PrivateKey
	hashFunc   func() hash.Hash
	encoding   string
}

// NewSecp256K1Signer creates a new instance of Secp256K1Signer.
func NewSecp256K1Signer(hashAlg string,
	curve string,
	encoding string,
	keyValue []byte) (*Secp256K1Signer, error) {
	privKey := new(ecdsa.PrivateKey)
	c := GetCurve(curve)
	privKey.PublicKey.Curve = c
	privKey.D = new(big.Int).SetBytes(keyValue)
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(keyValue)

	return NewSecp256K1SignerFromPrivateKey(hashAlg, encoding, privKey)
}

// NewSecp256K1SignerFromPrivateKey creates a new instance of Secp256K1Signer.
func NewSecp256K1SignerFromPrivateKey(hashAlg string, encoding string,
	privateKey *ecdsa.PrivateKey) (*Secp256K1Signer, error) {
	if privateKey.Curve == nil {
		return nil, errors.New("secp256k1_signer: privateKey.Curve can't be nil")
	}

	curve := ConvertCurveName(privateKey.Curve.Params().Name)
	if err := ValidateSecp256K1Params(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("secp256k1_signer: %w", err)
	}

	hashFunc := subtle.GetHashFunc(hashAlg)

	return &Secp256K1Signer{
		privateKey: privateKey,
		hashFunc:   hashFunc,
		encoding:   encoding,
	}, nil
}

// Sign computes a signature for the given data.
func (e *Secp256K1Signer) Sign(data []byte) ([]byte, error) {
	hashed, err := subtle.ComputeHash(e.hashFunc, data)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer: signing failed: %w", err)
	}

	// format the signature
	sig := NewSecp256K1Signature(r, s)

	ret, err := sig.EncodeSecp256K1Signature(e.encoding, e.privateKey.PublicKey.Curve.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer: signing failed: %w", err)
	}

	return ret, nil
}

// ConvertCurveName converts different forms of a curve name to the name that tink recognizes.
func ConvertCurveName(name string) string {
	switch name {
	case "secp256k1", "secp256K1":
		return "SECP256K1"
	default:
		return ""
	}
}
