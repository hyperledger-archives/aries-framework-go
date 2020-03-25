/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package ed25519signature2018 implements the Ed25519Signature2018 signature suite
// for the Linked Data Signatures [LD-SIGNATURES] specification.
// It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION]
// to transform the input document into its canonical form.
// It uses SHA-512 [RFC6234] as the message digest algorithm and
// Ed25519 [ED25519] as the signature algorithm.
package ed25519signature2018

import (
	"crypto/sha256"
	"errors"

	"github.com/piprate/json-gold/ld"

	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

// SignatureSuite implements ed25519 signature suite
type SignatureSuite struct {
	signer       signer
	verifier     verifier
	compactProof bool
}

const (
	signatureType = "Ed25519Signature2018"
	format        = "application/n-quads"
)

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

type verifier interface {
	// Verify will verify a signature.
	Verify(pubKeyValue *sigverifier.PublicKey, doc, signature []byte) error
}

// SuiteOpt is the SignatureSuite option.
type SuiteOpt func(opts *SignatureSuite)

// WithSigner defines a signer for the Signature Suite.
func WithSigner(s signer) SuiteOpt {
	return func(opts *SignatureSuite) {
		opts.signer = s
	}
}

// WithVerifier defines a verifier for the Signature Suite.
func WithVerifier(v verifier) SuiteOpt {
	return func(opts *SignatureSuite) {
		opts.verifier = v
	}
}

// WithCompactProof indicates that proof compaction is needed, by default it is not done.
func WithCompactProof() SuiteOpt {
	return func(opts *SignatureSuite) {
		opts.compactProof = true
	}
}

// New an instance of ed25519 signature suite
func New(opts ...SuiteOpt) *SignatureSuite {
	suite := &SignatureSuite{}

	for _, opt := range opts {
		opt(suite)
	}

	return suite
}

// GetCanonicalDocument will return normalized/canonical version of the document
// Ed25519Signature2018 signature SignatureSuite uses RDF Dataset Normalization as canonicalization algorithm
func (s *SignatureSuite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Format = format
	options.ProduceGeneralizedRdf = true

	canonicalDoc, err := proc.Normalize(doc, options)
	if err != nil {
		return nil, err
	}

	return []byte(canonicalDoc.(string)), nil
}

// GetDigest returns document digest
func (s *SignatureSuite) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}

// Verify will verify a signature.
func (s *SignatureSuite) Verify(pubKeyValue *sigverifier.PublicKey, doc, signature []byte) error {
	if s.verifier == nil {
		return ErrVerifierNotDefined
	}

	return s.verifier.Verify(pubKeyValue, doc, signature)
}

// Sign will sign input data.
func (s *SignatureSuite) Sign(data []byte) ([]byte, error) {
	if s.signer == nil {
		return nil, ErrSignerNotDefined
	}

	return s.signer.Sign(data)
}

// Accept will accept only ed25519 signature type
func (s *SignatureSuite) Accept(t string) bool {
	return t == signatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (s *SignatureSuite) CompactProof() bool {
	return s.compactProof
}

// ErrSignerNotDefined is returned when Sign() is called but signer option is not defined.
var ErrSignerNotDefined = errors.New("signer is not defined")

// ErrVerifierNotDefined is returned when Verify() is called but verifier option is not defined.
var ErrVerifierNotDefined = errors.New("verifier is not defined")
