/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/google/tink/go/subtle"
)

var errInvalidSecp256K1Signature = errors.New("secp256k1_verifier: invalid signature")

// ECDSAVerifier is an implementation of Verifier for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	hashFunc  func() hash.Hash
	encoding  string
}

// NewSecp256K1Verifier creates a new instance of Secp256K1Verifier.
func NewSecp256K1Verifier(hashAlg, curve, encoding string, x, y []byte) (*ECDSAVerifier, error) {
	publicKey := &ecdsa.PublicKey{
		Curve: GetCurve(curve),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	return NewSecp256K1VerifierFromPublicKey(hashAlg, encoding, publicKey)
}

// NewSecp256K1VerifierFromPublicKey creates a new instance of ECDSAVerifier.
func NewSecp256K1VerifierFromPublicKey(hashAlg, encoding string, publicKey *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if publicKey.Curve == nil {
		return nil, errors.New("ecdsa_verifier: invalid curve")
	}

	curve := ConvertCurveName(publicKey.Curve.Params().Name)
	if err := ValidateSecp256K1Params(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_verifier: %w", err)
	}

	hashFunc := subtle.GetHashFunc(hashAlg)

	return &ECDSAVerifier{
		publicKey: publicKey,
		hashFunc:  hashFunc,
		encoding:  encoding,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *ECDSAVerifier) Verify(signatureBytes, data []byte) error {
	signature, err := DecodeSecp256K1Signature(signatureBytes, e.encoding)
	if err != nil {
		return fmt.Errorf("secp256k1_verifier: %w", err)
	}

	hashed, err := subtle.ComputeHash(e.hashFunc, data)
	if err != nil {
		return err
	}

	valid := ecdsa.Verify(e.publicKey, hashed, signature.R, signature.S)
	if !valid {
		return errInvalidSecp256K1Signature
	}

	return nil
}
