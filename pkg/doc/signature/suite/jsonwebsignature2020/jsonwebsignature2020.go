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
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// Suite implements jsonWebSignature2020 signature suite.
type Suite = jsonwebsignature2020.Suite

// New an instance of Linked Data Signatures for JWS suite.
func New(opts ...suite.Opt) *Suite {
	return jsonwebsignature2020.New(opts...)
}

// NewPublicKeyVerifier creates a signature verifier that verifies a Ed25519 / EC (P-256, P-384, P-521, secp256k1) / RSA
// signature taking public key bytes and / or JSON Web Key as input.
// The list of Supported JWS algorithms of JsonWebSignature2020 is defined here:
// https://github.com/transmute-industries/lds-jws2020#supported-jws-algs
func NewPublicKeyVerifier() *verifier.PublicKeyVerifier {
	return jsonwebsignature2020.NewPublicKeyVerifier()
}
