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

	r3 := bls12381.NewFr()
	r3.Inverse(r1)

	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.A, frToRepr(r1))

	aBar := g1.New()
	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, frToRepr(signature.E))
	g1.MulScalar(aBar, b, frToRepr(r1))
	g1.Sub(aBar, aBar, aBarDenom)

	commitmentBasesCount := 2
	cbD := newCommitmentBuilder(commitmentBasesCount)
	cbD.add(b, r1)
	cbD.add(pubKey.Q1, r2)
	d := cbD.build()

	sPrime := bls12381.NewFr()
	sPrime.Mul(r2, r3)
	sPrime.Add(sPrime, signature.S)

	pokVC1, secrets1 := newVC1Signature(aPrime, pubKey.Q1, signature.E, r2)

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

func newVC1Signature(aPrime *bls12381.PointG1, q1 *bls12381.PointG1,
	e, r2 *bls12381.Fr) (*ProverCommittedG1, []*bls12381.Fr) {
	committing1 := NewProverCommittingG1()
	secrets1 := make([]*bls12381.Fr, 2)

	committing1.Commit(aPrime)
	secrets1[0] = e

	committing1.Commit(q1)
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
	secrets2 = append(secrets2, r3)

	committing2.Commit(pubKey.Q1)
	secrets2 = append(secrets2, sPrime)

	for i := 0; i < messagesCount; i++ {
		if _, ok := revealedMessages[i]; ok {
			continue
		}

		committing2.Commit(pubKey.H[i])

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
	challengeBytes := g1.ToUncompressed(pos.aPrime)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(pos.aBar)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(pos.d)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(pos.pokVC1.commitment)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(pos.pokVC2.commitment)...)
	r := len(pos.revealedMessages)
	idxs := make([]byte, 8*r)
	msgs := make([]byte, 0)
	challengeBytes = append(challengeBytes, i2os8(uint64(r))...)
	for i, m := range pos.revealedMessages {
		idxs = append(idxs, i2os8(uint64(i))...)
		msgs = append(msgs, m.FR.ToBytes()...)
	}
	challengeBytes = append(challengeBytes, idxs...)
	challengeBytes = append(challengeBytes, msgs...)

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
		s.Add(g.blindingFactors[i], c)
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

// Modified Finish() for case where first element should be neg
func (pc *ProverCommittingG1) FinishMod() *ProverCommittedG1 {
	blindings := make([]*bls12381.Fr, 0)
	copy(blindings, pc.blindingFactors)
	negFirst := bls12381.NewFr()
	negFirst.Neg(blindings[0])
	blindings[0] = negFirst
	commitment := sumOfG1Products(pc.bases, blindings)

	return &ProverCommittedG1{
		bases:           pc.bases,
		blindingFactors: pc.blindingFactors,
		commitment:      commitment,
	}
}
