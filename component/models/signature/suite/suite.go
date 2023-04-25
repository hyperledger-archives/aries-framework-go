/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package suite

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
)

// SignatureSuite defines general signature suite structure.
type SignatureSuite struct {
	Signer         signer
	Verifier       verifier
	CompactedProof bool
}

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
type Opt func(opts *SignatureSuite)

// WithSigner defines a signer for the Signature Suite.
func WithSigner(s signer) Opt {
	return func(opts *SignatureSuite) {
		opts.Signer = s
	}
}

// WithVerifier defines a verifier for the Signature Suite.
func WithVerifier(v verifier) Opt {
	return func(opts *SignatureSuite) {
		opts.Verifier = v
	}
}

// WithCompactProof indicates that proof compaction is needed, by default it is not done.
func WithCompactProof() Opt {
	return func(opts *SignatureSuite) {
		opts.CompactedProof = true
	}
}

// InitSuiteOptions initializes signature suite with options.
func InitSuiteOptions(suite *SignatureSuite, opts ...Opt) *SignatureSuite {
	for _, opt := range opts {
		opt(suite)
	}

	return suite
}

// Verify will verify a signature.
func (s *SignatureSuite) Verify(pubKeyValue *api.PublicKey, doc, signature []byte) error {
	if s.Verifier == nil {
		return ErrVerifierNotDefined
	}

	return s.Verifier.Verify(pubKeyValue, doc, signature)
}

// Sign will sign input data.
func (s *SignatureSuite) Sign(data []byte) ([]byte, error) {
	if s.Signer == nil {
		return nil, ErrSignerNotDefined
	}

	return s.Signer.Sign(data)
}

// CompactProof indicates weather to compact the proof doc before canonization.
func (s *SignatureSuite) CompactProof() bool {
	return s.CompactedProof
}

// Alg will return algorithm.
func (s *SignatureSuite) Alg() string {
	return s.Signer.Alg()
}

// ErrSignerNotDefined is returned when Sign() is called but signer option is not defined.
var ErrSignerNotDefined = errors.New("signer is not defined")

// ErrVerifierNotDefined is returned when Verify() is called but verifier option is not defined.
var ErrVerifierNotDefined = errors.New("verifier is not defined")
