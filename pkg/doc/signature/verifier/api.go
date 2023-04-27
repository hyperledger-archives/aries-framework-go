/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"github.com/hyperledger/aries-framework-go/component/models/signature/api"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// TODO pull SignatureSuite interface and PublicKey type out into an API package

// SignatureSuite encapsulates signature suite methods required for signature verification.
type SignatureSuite = api.SignatureSuite

// PublicKey contains a result of public key resolution.
type PublicKey = api.PublicKey

// keyResolver encapsulates key resolution.
type keyResolver interface {
	// Resolve will return public key bytes and the type of public key
	Resolve(id string) (*api.PublicKey, error)
}

// DocumentVerifier implements JSON LD document proof verification.
type DocumentVerifier = verifier.DocumentVerifier

// New returns new instance of document verifier.
func New(resolver keyResolver, suites ...SignatureSuite) (*DocumentVerifier, error) {
	return verifier.New(resolver, suites...)
}

// PublicKeyVerifier makes signature verification using the public key
// based on one or several signature algorithms.
type PublicKeyVerifier = verifier.PublicKeyVerifier

// PublicKeyVerifierOpt is the PublicKeyVerifier functional option.
type PublicKeyVerifierOpt = verifier.PublicKeyVerifierOpt

// NewPublicKeyVerifier creates a new PublicKeyVerifier based on single signature algorithm.
func NewPublicKeyVerifier(sigAlg SignatureVerifier, opts ...PublicKeyVerifierOpt) *PublicKeyVerifier {
	return verifier.NewPublicKeyVerifier(sigAlg, opts...)
}

// NewCompositePublicKeyVerifier creates a new PublicKeyVerifier based on one or more signature algorithms.
func NewCompositePublicKeyVerifier(verifiers []SignatureVerifier, opts ...PublicKeyVerifierOpt) *PublicKeyVerifier {
	return verifier.NewCompositePublicKeyVerifier(verifiers, opts...)
}

// WithExactPublicKeyType option is used to check the type of the PublicKey.
func WithExactPublicKeyType(jwkType string) PublicKeyVerifierOpt {
	return verifier.WithExactPublicKeyType(jwkType)
}

// SignatureVerifier make signature verification of a certain algorithm (e.g. Ed25519 or ECDSA secp256k1).
type SignatureVerifier = verifier.SignatureVerifier

// Ed25519SignatureVerifier verifies a Ed25519 signature taking Ed25519 public key bytes as input.
type Ed25519SignatureVerifier = verifier.Ed25519SignatureVerifier

// NewEd25519SignatureVerifier creates a new Ed25519SignatureVerifier.
func NewEd25519SignatureVerifier() *Ed25519SignatureVerifier {
	return verifier.NewEd25519SignatureVerifier()
}

// RSAPS256SignatureVerifier verifies a Ed25519 signature taking RSA public key bytes as input.
type RSAPS256SignatureVerifier = verifier.RSAPS256SignatureVerifier

// NewRSAPS256SignatureVerifier creates a new RSAPS256SignatureVerifier.
func NewRSAPS256SignatureVerifier() *RSAPS256SignatureVerifier {
	return verifier.NewRSAPS256SignatureVerifier()
}

// RSARS256SignatureVerifier verifies a Ed25519 signature taking RSA public key bytes as input.
type RSARS256SignatureVerifier = verifier.RSARS256SignatureVerifier

// NewRSARS256SignatureVerifier creates a new RSARS256SignatureVerifier.
func NewRSARS256SignatureVerifier() *RSARS256SignatureVerifier {
	return verifier.NewRSARS256SignatureVerifier()
}

// ECDSASignatureVerifier verifies elliptic curve signatures.
type ECDSASignatureVerifier = verifier.ECDSASignatureVerifier

// NewECDSASecp256k1SignatureVerifier creates a new signature verifier that verifies a ECDSA secp256k1 signature
// taking public key bytes and JSON Web Key as input.
func NewECDSASecp256k1SignatureVerifier() *ECDSASignatureVerifier {
	return verifier.NewECDSASecp256k1SignatureVerifier()
}

// NewECDSAES256SignatureVerifier creates a new signature verifier that verifies a ECDSA P-256 signature
// taking public key bytes and JSON Web Key as input.
func NewECDSAES256SignatureVerifier() *ECDSASignatureVerifier {
	return verifier.NewECDSAES256SignatureVerifier()
}

// NewECDSAES384SignatureVerifier creates a new signature verifier that verifies a ECDSA P-384 signature
// taking public key bytes and JSON Web Key as input.
func NewECDSAES384SignatureVerifier() *ECDSASignatureVerifier {
	return verifier.NewECDSAES384SignatureVerifier()
}

// NewECDSAES521SignatureVerifier creates a new signature verifier that verifies a ECDSA P-521 signature
// taking public key bytes and JSON Web Key as input.
func NewECDSAES521SignatureVerifier() *ECDSASignatureVerifier {
	return verifier.NewECDSAES521SignatureVerifier()
}

// NewBBSG2SignatureVerifier creates a new BBSG2SignatureVerifier.
func NewBBSG2SignatureVerifier() *BBSG2SignatureVerifier {
	return verifier.NewBBSG2SignatureVerifier()
}

// BBSG2SignatureVerifier is a signature verifier that verifies a BBS+ Signature
// taking Bls12381G2Key2020 public key bytes as input.
// The reference implementation https://github.com/mattrglobal/bls12381-key-pair supports public key bytes only,
// JWK is not supported.
type BBSG2SignatureVerifier = verifier.BBSG2SignatureVerifier

// NewBBSG2SignatureProofVerifier creates a new BBSG2SignatureProofVerifier.
func NewBBSG2SignatureProofVerifier(nonce []byte) *BBSG2SignatureProofVerifier {
	return verifier.NewBBSG2SignatureProofVerifier(nonce)
}

// BBSG2SignatureProofVerifier is a signature verifier that verifies a BBS+ Signature Proof
// taking Bls12381G2Key2020 public key bytes as input.
// The reference implementation https://github.com/mattrglobal/bls12381-key-pair supports public key bytes only,
// JWK is not supported.
type BBSG2SignatureProofVerifier = verifier.BBSG2SignatureProofVerifier
