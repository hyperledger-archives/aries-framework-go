/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package ecdsasecp256k1signature2019 implements the EcdsaSecp256k1Signature2019 signature suite
// for the Linked Data Signatures specification (https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/).
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm.
// Supported signature algorithms depend on the signer/verifier provided as options to the New().
package ecdsasecp256k1signature2019

import (
	"crypto/sha256"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
)

// Suite implements EcdsaSecp256k1Signature2019 signature suite.
type Suite struct {
	suite.SignatureSuite
	jsonldProcessor *processor.Processor
}

const (
	signatureType = "EcdsaSecp256k1Signature2019"
	jwkType       = "EcdsaSecp256k1VerificationKey2019"
	rdfDataSetAlg = "URDNA2015"
)

// New an instance of Linked Data Signatures for JWS suite.
func New(opts ...suite.Opt) *Suite {
	s := &Suite{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}

	suite.InitSuiteOptions(&s.SignatureSuite, opts...)

	return s
}

// GetCanonicalDocument will return normalized/canonical version of the document.
// EcdsaSecp256k1Signature2019 signature suite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Suite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *Suite) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}

// Accept will accept only EcdsaSecp256k1Signature2019 signature type.
func (s *Suite) Accept(t string) bool {
	return t == signatureType
}
