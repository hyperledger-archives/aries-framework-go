/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package jsonwebsignature2020 implements the JsonWebSignature2020 signature suite
// for the Linked Data Signatures specification (https://github.com/transmute-industries/lds-jws2020).
// It uses the RDF Dataset Normalization Algorithm
// to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm.
// Supported signature algorithms depend on the signer/verifier provided as options to the New().
// According to the suite specification, signer/verifier must support the following algorithms:
// kty | crvOrSize | alg
// OKP | Ed25519   | EdDSA
// EC  | secp256k1 | ES256K
// RSA | 2048      | PS256
// EC  | P-256     | ES256
// EC  | P-384     | ES384
// EC  | P-521     | ES512
package jsonwebsignature2020

import (
	"crypto/sha256"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
)

// Suite implements jsonWebSignature2020 signature suite.
type Suite struct {
	suite.SignatureSuite
	jsonldProcessor *processor.Processor
}

const (
	signatureType = "JsonWebSignature2020"
	jwkType       = "JsonWebKey2020"
	rdfDataSetAlg = "URDNA2015"
)

// New an instance of Linked Data Signatures for JWS suite.
func New(opts ...suite.Opt) *Suite {
	s := &Suite{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}

	suite.InitSuiteOptions(&s.SignatureSuite, opts...)

	return s
}

// GetCanonicalDocument will return normalized/canonical version of the document
// Ed25519Signature2018 signature SignatureSuite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Suite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest.
func (s *Suite) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}

// Accept will accept only Linked Data Signatures for JWS.
func (s *Suite) Accept(t string) bool {
	return t == signatureType
}
