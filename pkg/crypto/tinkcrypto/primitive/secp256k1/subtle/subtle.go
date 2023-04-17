/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package subtle provides subtle implementations of the digital signature primitive.
package subtle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	secp256k1subtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

// Secp256k1Signature is a struct holding the r and s values of an secp256k1 signature.
type Secp256k1Signature = secp256k1subtle.Secp256k1Signature

// NewSecp256K1Signature creates a new Secp256k1Signature instance.
func NewSecp256K1Signature(r, s *big.Int) *Secp256k1Signature {
	return secp256k1subtle.NewSecp256K1Signature(r, s)
}

// DecodeSecp256K1Signature creates a new secp256k1 signature using the given byte slice.
// The function assumes that the byte slice is the concatenation of the BigEndian
// representation of two big integer r and s.
func DecodeSecp256K1Signature(encodedBytes []byte, encoding string) (*Secp256k1Signature, error) {
	return secp256k1subtle.DecodeSecp256K1Signature(encodedBytes, encoding)
}

// ValidateSecp256K1Params validates secp256k1 parameters.
// The hash's strength must not be weaker than the curve's strength.
// DER and IEEE_P1363 encodings are supported.
func ValidateSecp256K1Params(hashAlg, curve, encoding string) error {
	return secp256k1subtle.ValidateSecp256K1Params(hashAlg, curve, encoding)
}

// GetCurve returns the curve object that corresponds to the given curve type.
// It returns null if the curve type is not supported.
func GetCurve(curve string) elliptic.Curve {
	return secp256k1subtle.GetCurve(curve)
}

// Secp256K1Signer is an implementation of Signer for secp256k1 Secp256k2 (Koblitz curve).
// At the moment, the implementation only accepts DER encoding.
type Secp256K1Signer = secp256k1subtle.Secp256K1Signer

// NewSecp256K1Signer creates a new instance of Secp256K1Signer.
func NewSecp256K1Signer(hashAlg string,
	curve string,
	encoding string,
	keyValue []byte) (*Secp256K1Signer, error) {
	return secp256k1subtle.NewSecp256K1Signer(hashAlg, curve, encoding, keyValue)
}

// NewSecp256K1SignerFromPrivateKey creates a new instance of Secp256K1Signer.
func NewSecp256K1SignerFromPrivateKey(hashAlg string, encoding string,
	privateKey *ecdsa.PrivateKey) (*Secp256K1Signer, error) {
	return secp256k1subtle.NewSecp256K1SignerFromPrivateKey(hashAlg, encoding, privateKey)
}

// ConvertCurveName converts different forms of a curve name to the name that tink recognizes.
func ConvertCurveName(name string) string {
	return secp256k1subtle.ConvertCurveName(name)
}

// ECDSAVerifier is an implementation of Verifier for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ECDSAVerifier = secp256k1subtle.ECDSAVerifier

// NewSecp256K1Verifier creates a new instance of Secp256K1Verifier.
func NewSecp256K1Verifier(hashAlg, curve, encoding string, x, y []byte) (*ECDSAVerifier, error) {
	return secp256k1subtle.NewSecp256K1Verifier(hashAlg, curve, encoding, x, y)
}

// NewSecp256K1VerifierFromPublicKey creates a new instance of ECDSAVerifier.
func NewSecp256K1VerifierFromPublicKey(hashAlg, encoding string, publicKey *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return secp256k1subtle.NewSecp256K1VerifierFromPublicKey(hashAlg, encoding, publicKey)
}
