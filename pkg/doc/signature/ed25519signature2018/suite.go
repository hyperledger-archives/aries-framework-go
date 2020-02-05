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
	"crypto/ed25519"
	"crypto/sha512"
	"errors"

	"github.com/piprate/json-gold/ld"
)

// SignatureSuite implements ed25519 signature suite
type SignatureSuite struct {
	signer signer
}

const (
	signatureType = "Ed25519Signature2018"
	format        = "application/n-quads"
)

type signer interface {
	// Sign will sign document and return signature
	Sign(data []byte) ([]byte, error)
}

// SuiteOpt is the SignatureSuite option.
type SuiteOpt func(opts *SignatureSuite)

// WithSigner defines a signer for the Signature Suite.
func WithSigner(s signer) SuiteOpt {
	return func(opts *SignatureSuite) {
		opts.signer = s
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
	digest := sha512.Sum512(doc)
	return digest[:]
}

// Verify will verify a signature.
func (s *SignatureSuite) Verify(pubKey, doc, signature []byte) error {
	// ed25519 panics if key size is wrong
	if l := len(pubKey); l != ed25519.PublicKeySize {
		return errors.New("ed25519: bad public key length")
	}

	verified := ed25519.Verify(pubKey, doc, signature)
	if !verified {
		return errors.New("signature doesn't match")
	}

	return nil
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

// ErrSignerNotDefined is returned when Sign() is called but signer option is not defined.
var ErrSignerNotDefined = errors.New("signer is not defined")
