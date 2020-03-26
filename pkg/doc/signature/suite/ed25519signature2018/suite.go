/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package ed25519signature2018 implements the Ed25519Signature2018 signature suite
// for the Linked Data Signatures [LD-SIGNATURES] specification.
// It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION]
// to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm and
// Ed25519 [ED25519] as the signature algorithm.
package ed25519signature2018

import (
	"crypto/sha256"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
)

// Suite implements ed25519 signature suite
type Suite struct {
	suite.SignatureSuite
}

const (
	signatureType = "Ed25519Signature2018"
	format        = "application/n-quads"
)

// New an instance of ed25519 signature suite
func New(opts ...suite.Opt) *Suite {
	s := &Suite{}

	suite.InitSuiteOptions(&s.SignatureSuite, opts...)

	return s
}

// GetCanonicalDocument will return normalized/canonical version of the document
// Ed25519Signature2018 signature SignatureSuite uses RDF Dataset Normalization as canonicalization algorithm
func (s *Suite) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
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
func (s *Suite) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}

// Accept will accept only ed25519 signature type
func (s *Suite) Accept(t string) bool {
	return t == signatureType
}
