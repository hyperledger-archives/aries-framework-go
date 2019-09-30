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
	"crypto/sha512"
	"errors"

	"crypto/ed25519"

	"github.com/piprate/json-gold/ld"
)

// SignatureSuite implements ed25519 signature suite
type SignatureSuite struct {
}

const (
	signatureType = "Ed25519Signature2018"
	format        = "application/n-quads"
)

// New an instance of ed25519 signature suite
func New() *SignatureSuite {
	return &SignatureSuite{}
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

// Verify will verify ed25519 signature against public key
func (s *SignatureSuite) Verify(pubKey, doc, signature []byte) error {
	verified := ed25519.Verify(pubKey, doc, signature)
	if !verified {
		return errors.New("signature doesn't match")
	}
	return nil
}

// Sign will return ed25519 signature
func (s *SignatureSuite) Sign(privKey, doc []byte) ([]byte, error) {
	signature := ed25519.Sign(privKey, doc)
	return signature, nil
}

// Accept will accept only ed25519 signature type
func (s *SignatureSuite) Accept(t string) bool {
	return t == signatureType
}
