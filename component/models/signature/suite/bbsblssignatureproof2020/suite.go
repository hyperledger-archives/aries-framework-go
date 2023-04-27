/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbsblssignatureproof2020

// Package bbsblssignatureproof2020 implements the BBS+ Signature Proof Suite 2020 signature suite
// (https://w3c-ccg.github.io/ldp-bbs2020) in conjunction with the signing and verification algorithms of the
// Linked Data Proofs.
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the statement digest algorithm.
// It uses BBS+ signature algorithm (https://mattrglobal.github.io/bbs-signatures-spec/).
// It uses BLS12-381 pairing-friendly curve (https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03).

import (
	"strings"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
)

// Suite implements BbsBlsSignatureProof2020 signature suite.
type Suite struct {
	suite.SignatureSuite
	jsonldProcessor *processor.Processor
}

const (
	signatureType      = "BbsBlsSignature2020"
	signatureProofType = "BbsBlsSignatureProof2020"
	rdfDataSetAlg      = "URDNA2015"
)

// New an instance of Linked Data Signatures for the suite.
func New(opts ...suite.Opt) *Suite {
	s := &Suite{jsonldProcessor: processor.NewProcessor(rdfDataSetAlg)}

	suite.InitSuiteOptions(&s.SignatureSuite, opts...)

	return s
}

// GetCanonicalDocument will return normalized/canonical version of the document.
// BbsBlsSignatureProof2020 signature suite uses RDF Dataset Normalization as canonicalization algorithm.
func (s *Suite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	if v, ok := doc["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, signatureProofType) {
			docType = strings.Replace(docType, signatureProofType, signatureType, 1)
			doc["type"] = docType
		}
	}

	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

// GetDigest returns the doc itself as we would process N-Quads statements as messages to be signed/verified.
func (s *Suite) GetDigest(doc []byte) []byte {
	return doc
}

// Accept will accept only BbsBlsSignatureProof2020 signature type.
func (s *Suite) Accept(t string) bool {
	return t == signatureProofType
}
