/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package bbsblssignature2020 implements the BBS+ Signature Suite 2020 signature suite
// (https://w3c-ccg.github.io/ldp-bbs2020) in conjunction with the signing and verification algorithms of the
// Linked Data Proofs.
// It uses the RDF Dataset Normalization Algorithm to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the statement digest algorithm.
// It uses BBS+ signature algorithm (https://mattrglobal.github.io/bbs-signatures-spec/).
// It uses BLS12-381 pairing-friendly curve (https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03).
package bbsblssignature2020

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// Suite implements BbsBlsSignature2020 signature suite.
type Suite = bbsblssignature2020.Suite

const (
	// SignatureType is the BbsBlsSignature2020 type string.
	SignatureType = "BbsBlsSignature2020"
)

// New an instance of Linked Data Signatures for JWS suite.
func New(opts ...suite.Opt) *Suite {
	return bbsblssignature2020.New(opts...)
}

// NewG2PublicKeyVerifier creates a signature verifier that verifies a BbsBlsSignature2020 signature
// taking Bls12381G2Key2020 public key bytes as input.
func NewG2PublicKeyVerifier() *verifier.PublicKeyVerifier {
	return bbsblssignature2020.NewG2PublicKeyVerifier()
}
