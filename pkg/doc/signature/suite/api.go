/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
)

// SignatureSuite defines general signature suite structure.
type SignatureSuite = suite.SignatureSuite

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
	// Alg return alg.
	Alg() string
}

type verifier interface {
	// Verify will verify a signature.
	Verify(pubKeyValue *api.PublicKey, doc, signature []byte) error
}

// Opt is the SignatureSuite option.
type Opt = suite.Opt

// WithSigner defines a signer for the Signature Suite.
func WithSigner(s signer) Opt {
	return suite.WithSigner(s)
}

// WithVerifier defines a verifier for the Signature Suite.
func WithVerifier(v verifier) Opt {
	return suite.WithVerifier(v)
}

// WithCompactProof indicates that proof compaction is needed, by default it is not done.
func WithCompactProof() Opt {
	return suite.WithCompactProof()
}

// InitSuiteOptions initializes signature suite with options.
func InitSuiteOptions(signatureSuite *SignatureSuite, opts ...Opt) *SignatureSuite {
	return suite.InitSuiteOptions(signatureSuite, opts...)
}

// CryptoSigner defines signer based on crypto.
type CryptoSigner = suite.CryptoSigner

// NewCryptoSigner creates a new CryptoSigner.
func NewCryptoSigner(cr crypto.Crypto, kh interface{}) *CryptoSigner {
	return suite.NewCryptoSigner(cr, kh)
}

// CryptoVerifier defines signature verifier based on crypto.
type CryptoVerifier = suite.CryptoVerifier

// NewCryptoVerifier creates a new CryptoVerifier.
func NewCryptoVerifier(cr crypto.Crypto) *CryptoVerifier {
	return suite.NewCryptoVerifier(cr)
}

// ErrSignerNotDefined is returned when Sign() is called but signer option is not defined.
var ErrSignerNotDefined = suite.ErrSignerNotDefined

// ErrVerifierNotDefined is returned when Verify() is called but verifier option is not defined.
var ErrVerifierNotDefined = suite.ErrVerifierNotDefined
