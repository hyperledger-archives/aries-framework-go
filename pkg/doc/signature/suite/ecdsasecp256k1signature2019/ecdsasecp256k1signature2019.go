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
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// Suite implements EcdsaSecp256k1Signature2019 signature suite.
type Suite = ecdsasecp256k1signature2019.Suite

// New an instance of Linked Data Signatures for JWS suite.
func New(opts ...suite.Opt) *Suite {
	return ecdsasecp256k1signature2019.New(opts...)
}

// NewPublicKeyVerifier creates a signature verifier that verifies a ECDSA secp256k1 signature
// taking Ed25519 public key bytes as input.
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return ecdsasecp256k1signature2019.NewPublicKeyVerifier()
}
