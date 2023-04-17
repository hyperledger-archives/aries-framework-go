/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

// PoKOfSignature is Proof of Knowledge of a Signature that is used by the prover to construct PoKOfSignatureProof.
type PoKOfSignature struct {
	aPrime *bls12381.PointG1
	aBar   *bls12381.PointG1
	d      *bls12381.PointG1

	pokVC1   *ProverCommittedG1
	secrets1 []*bls12381.Fr

	pokVC2   *ProverCommittedG1
	secrets2 []*bls12381.Fr

	revealedMessages map[int]*SignatureMessage
}

// NewPoKOfSignature creates a new PoKOfSignature.
func NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {
	err := signature.Verify(messages, pubKey)
	if err != nil {
		return nil, fmt.Errorf("verify input signature: %w", err)
	}

	r1, r2 := createRandSignatureFr(), createRandSignatureFr()
	b := computeB(signature.S, messages, pubKey)
	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.A, frToRepr(r1))

	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, frToRepr(signature.E))

	aBar := g1.New()
	g1.MulScalar(aBar, b, frToRepr(r1))
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := bls12381.NewFr()
	r2D.Neg(r2)

	commitmentBasesCount := 2
	cb := newCommitmentBuilder(commitmentBasesCount)
	cb.add(b, r1)
	cb.add(pubKey.h0, r2D)

	d := cb.build()
	r3 := bls12381.NewFr()
	r3.Inverse(r1)

	sPrime := bls12381.NewFr()
	sPrime.Mul(r2, r3)
	sPrime.Neg(sPrime)
	sPrime.Add(sPrime, signature.S)

	pokVC1, secrets1 := newVC1Signature(aPrime, pubKey.h0, signature.E, r2)

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))

	if len(messages) < len(revealedIndexes) {
		return nil, fmt.Errorf("invalid size: %d revealed indexes is larger than %d messages", len(revealedIndexes),
			len(messages))
	}

	for _, ind := range revealedIndexes {
		revealedMessages[ind] = messages[ind]
	}

	pokVC2, secrets2 := newVC2Signature(d, r3, pubKey, sPrime, messages, revealedMessages)

	return &PoKOfSignature{
		aPrime:           aPrime,
		aBar:             aBar,
		d:                d,
		pokVC1:           pokVC1,
		secrets1:         secrets1,
		pokVC2:           pokVC2,
		secrets2:         secrets2,
		revealedMessages: revealedMessages,
	}, nil
}

func newVC1Signature(aPrime *bls12381.PointG1, h0 *bls12381.PointG1,
	e, r2 *bls12381.Fr) (*ProverCommittedG1, []*bls12381.Fr) {
	committing1 := NewProverCommittingG1()
	secrets1 := make([]*bls12381.Fr, 2)

	committing1.Commit(aPrime)

	sigE := bls12381.NewFr()
	sigE.Neg(e)
	secrets1[0] = sigE

	committing1.Commit(h0)

	secrets1[1] = r2
	pokVC1 := committing1.Finish()

	return pokVC1, secrets1
}

func newVC2Signature(d *bls12381.PointG1, r3 *bls12381.Fr, pubKey *PublicKeyWithGenerators, sPrime *bls12381.Fr,
	messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage) (*ProverCommittedG1, []*bls12381.Fr) {
	messagesCount := len(messages)
	committing2 := NewProverCommittingG1()
	baseSecretsCount := 2
	secrets2 := make([]*bls12381.Fr, 0, baseSecretsCount+messagesCount)

	committing2.Commit(d)

	r3D := bls12381.NewFr()
	r3D.Neg(r3)

	secrets2 = append(secrets2, r3D)

	committing2.Commit(pubKey.h0)

	secrets2 = append(secrets2, sPrime)

	for i := 0; i < messagesCount; i++ {
		if _, ok := revealedMessages[i]; ok {
			continue
		}

		committing2.Commit(pubKey.h[i])

		sourceFR := messages[i].FR
		hiddenFRCopy := bls12381.NewFr()
		hiddenFRCopy.Set(sourceFR)

		secrets2 = append(secrets2, hiddenFRCopy)
	}

	pokVC2 := committing2.Finish()

	return pokVC2, secrets2
}

// ToBytes converts PoKOfSignature to bytes.
func (pos *PoKOfSignature) ToBytes() []byte {
	challengeBytes := g1.ToUncompressed(pos.aBar)
	challengeBytes = append(challengeBytes, pos.pokVC1.ToBytes()...)
	challengeBytes = append(challengeBytes, pos.pokVC2.ToBytes()...)

	return challengeBytes
}

// GenerateProof generates PoKOfSignatureProof proof from PoKOfSignature signature.
func (pos *PoKOfSignature) GenerateProof(challengeHash *bls12381.Fr) *PoKOfSignatureProof {
	return &PoKOfSignatureProof{
		aPrime:   pos.aPrime,
		aBar:     pos.aBar,
		d:        pos.d,
		proofVC1: pos.pokVC1.GenerateProof(challengeHash, pos.secrets1),
		proofVC2: pos.pokVC2.GenerateProof(challengeHash, pos.secrets2),
	}
}

// ProverCommittedG1 helps to generate a ProofG1.
type ProverCommittedG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
	commitment      *bls12381.PointG1
}

// ToBytes converts ProverCommittedG1 to bytes.
func (g *ProverCommittedG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	for _, base := range g.bases {
		bytes = append(bytes, g1.ToUncompressed(base)...)
	}

	return append(bytes, g1.ToUncompressed(g.commitment)...)
}

// GenerateProof generates proof ProofG1 for all secrets.
func (g *ProverCommittedG1) GenerateProof(challenge *bls12381.Fr, secrets []*bls12381.Fr) *ProofG1 {
	responses := make([]*bls12381.Fr, len(g.bases))

	for i := range g.blindingFactors {
		c := bls12381.NewFr()
		c.Mul(challenge, secrets[i])

		s := bls12381.NewFr()
		s.Sub(g.blindingFactors[i], c)
		responses[i] = s
	}

	return &ProofG1{
		commitment: g.commitment,
		responses:  responses,
	}
}

// ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
type ProverCommittingG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
}

// NewProverCommittingG1 creates a new ProverCommittingG1.
func NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]*bls12381.PointG1, 0),
		blindingFactors: make([]*bls12381.Fr, 0),
	}
}

// Commit append a base point and randomly generated blinding factor.
func (pc *ProverCommittingG1) Commit(base *bls12381.PointG1) {
	pc.bases = append(pc.bases, base)
	r := createRandSignatureFr()
	pc.blindingFactors = append(pc.blindingFactors, r)
}

// Finish helps to generate ProverCommittedG1 after commitment of all base points.
func (pc *ProverCommittingG1) Finish() *ProverCommittedG1 {
	commitment := sumOfG1Products(pc.bases, pc.blindingFactors)

	return &ProverCommittedG1{
		bases:           pc.bases,
		blindingFactors: pc.blindingFactors,
		commitment:      commitment,
	}
}
