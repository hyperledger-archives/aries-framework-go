/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	ml "github.com/IBM/mathlib"
	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof = bbs.PoKOfSignatureProof

// ProofG1 is a proof of knowledge of a signature and hidden messages.
type ProofG1 = bbs.ProofG1

// NewProofG1 creates a new ProofG1.
func NewProofG1(commitment *ml.G1, responses []*ml.Zr) *ProofG1 {
	return bbs.NewProofG1(commitment, responses)
}

// ParseSignatureProof parses a signature proof.
func ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	return bbs.ParseSignatureProof(sigProofBytes)
}

// ParseProofG1 parses ProofG1 from bytes.
func ParseProofG1(bytes []byte) (*ProofG1, error) {
	return bbs.ParseProofG1(bytes)
}
