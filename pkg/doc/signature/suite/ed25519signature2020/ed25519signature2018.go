/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package ed25519signature2020 implements the Ed25519Signature2020 signature suite
// for the Linked Data Signatures [LD-SIGNATURES] specification.
// It uses the RDF Dataset Normalization Algorithm [RDF-DATASET-NORMALIZATION]
// to transform the input document into its canonical form.
// It uses SHA-256 [RFC6234] as the message digest algorithm and
// Ed25519 [ED25519] as the signature algorithm.
package ed25519signature2020

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// Suite implements ed25519 signature suite.
type Suite = ed25519signature2020.Suite

const (
	// SignatureType is the signature type for ed25519 keys.
	SignatureType = ed25519signature2020.SignatureType
)

// New an instance of ed25519 signature suite.
func New(opts ...suite.Opt) *Suite {
	return ed25519signature2020.New(opts...)
}

// NewPublicKeyVerifier creates a signature verifier that verifies a Ed25519 signature
// taking Ed25519 public key bytes as input.
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return ed25519signature2020.NewPublicKeyVerifier()
}
