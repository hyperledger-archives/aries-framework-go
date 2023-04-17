/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

// PoKOfSignature is Proof of Knowledge of a Signature that is used by the prover to construct PoKOfSignatureProof.
type PoKOfSignature = bbs.PoKOfSignature

// NewPoKOfSignature creates a new PoKOfSignature.
func NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {
	return bbs.NewPoKOfSignature(signature, messages, revealedIndexes, pubKey)
}

// ProverCommittedG1 helps to generate a ProofG1.
type ProverCommittedG1 = bbs.ProverCommittedG1

// ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
type ProverCommittingG1 = bbs.ProverCommittingG1
