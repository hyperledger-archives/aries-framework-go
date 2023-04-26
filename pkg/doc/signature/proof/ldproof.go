/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	ldproof "github.com/hyperledger/aries-framework-go/component/models/ld/proof"
)

// signatureSuite encapsulates signature suite methods required for normalizing document.
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool
}

// SignatureRepresentation defines a representation of signature value.
type SignatureRepresentation = ldproof.SignatureRepresentation

const (
	// SignatureProofValue uses "proofValue" field in a Proof to put/read a digital signature.
	SignatureProofValue = ldproof.SignatureProofValue

	// SignatureJWS uses "jws" field in a Proof as an element for representation of detached JSON Web Signatures.
	SignatureJWS = ldproof.SignatureJWS
)

// Proof is cryptographic proof of the integrity of the DID Document.
type Proof = ldproof.Proof

// NewProof creates new proof.
func NewProof(emap map[string]interface{}) (*Proof, error) {
	return ldproof.NewProof(emap)
}

// DecodeProofValue decodes proofValue basing on proof type.
func DecodeProofValue(s, proofType string) ([]byte, error) {
	return ldproof.DecodeProofValue(s, proofType)
}

// EncodeProofValue decodes proofValue basing on proof type.
func EncodeProofValue(proofValue []byte, proofType string) string {
	return ldproof.EncodeProofValue(proofValue, proofType)
}

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyData(suite signatureSuite, jsonldDoc map[string]interface{}, proof *Proof,
	opts ...processor.Opts) ([]byte, error) {
	return ldproof.CreateVerifyData(suite, jsonldDoc, proof, opts...)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func CreateVerifyHash(suite signatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...processor.Opts) ([]byte, error) {
	return ldproof.CreateVerifyHash(suite, jsonldDoc, proofOptions, opts...)
}

// CreateDetachedJWTHeader creates detached JWT header.
func CreateDetachedJWTHeader(alg string) string {
	return ldproof.CreateDetachedJWTHeader(alg)
}

// GetJWTSignature returns signature part of JWT.
func GetJWTSignature(jwt string) ([]byte, error) {
	return ldproof.GetJWTSignature(jwt)
}

// GetProofs gets proof(s) from LD Object.
func GetProofs(jsonLdObject map[string]interface{}) ([]*Proof, error) {
	return ldproof.GetProofs(jsonLdObject)
}

// AddProof adds a proof to LD Object.
func AddProof(jsonLdObject map[string]interface{}, proof *Proof) error {
	return ldproof.AddProof(jsonLdObject, proof)
}

// GetCopyWithoutProof gets copy of JSON LD Object without proofs (signatures).
func GetCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
	return ldproof.GetCopyWithoutProof(jsonLdObject)
}

// ErrProofNotFound is returned when proof is not found.
var ErrProofNotFound = ldproof.ErrProofNotFound
