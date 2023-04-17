/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"encoding/binary"
	"errors"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof struct {
	aPrime *bls12381.PointG1
	aBar   *bls12381.PointG1
	d      *bls12381.PointG1

	proofVC1 *ProofG1
	proofVC2 *ProofG1
}

// GetBytesForChallenge creates bytes for proof challenge.
func (sp *PoKOfSignatureProof) GetBytesForChallenge(revealedMessages map[int]*SignatureMessage,
	pubKey *PublicKeyWithGenerators) []byte {
	hiddenCount := pubKey.messagesCount - len(revealedMessages)

	bytesLen := (7 + hiddenCount) * g1UncompressedSize //nolint:gomnd
	bytes := make([]byte, 0, bytesLen)

	bytes = append(bytes, g1.ToUncompressed(sp.aBar)...)
	bytes = append(bytes, g1.ToUncompressed(sp.aPrime)...)
	bytes = append(bytes, g1.ToUncompressed(pubKey.h0)...)
	bytes = append(bytes, g1.ToUncompressed(sp.proofVC1.commitment)...)
	bytes = append(bytes, g1.ToUncompressed(sp.d)...)
	bytes = append(bytes, g1.ToUncompressed(pubKey.h0)...)

	for i := range pubKey.h {
		if _, ok := revealedMessages[i]; !ok {
			bytes = append(bytes, g1.ToUncompressed(pubKey.h[i])...)
		}
	}

	bytes = append(bytes, g1.ToUncompressed(sp.proofVC2.commitment)...)

	return bytes
}

// Verify verifies PoKOfSignatureProof.
func (sp *PoKOfSignatureProof) Verify(challenge *bls12381.Fr, pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {
	aBar := new(bls12381.PointG1)
	g1.Neg(aBar, sp.aBar)

	ok := compareTwoPairings(sp.aPrime, pubKey.w, aBar, g2.One())
	if !ok {
		return errors.New("bad signature")
	}

	err := sp.verifyVC1Proof(challenge, pubKey)
	if err != nil {
		return err
	}

	return sp.verifyVC2Proof(challenge, pubKey, revealedMessages, messages)
}

func (sp *PoKOfSignatureProof) verifyVC1Proof(challenge *bls12381.Fr, pubKey *PublicKeyWithGenerators) error {
	basesVC1 := []*bls12381.PointG1{sp.aPrime, pubKey.h0}
	aBarD := new(bls12381.PointG1)
	g1.Sub(aBarD, sp.aBar, sp.d)

	err := sp.proofVC1.Verify(basesVC1, aBarD, challenge)
	if err != nil {
		return errors.New("bad signature")
	}

	return nil
}

func (sp *PoKOfSignatureProof) verifyVC2Proof(challenge *bls12381.Fr, pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {
	revealedMessagesCount := len(revealedMessages)

	basesVC2 := make([]*bls12381.PointG1, 0, 2+pubKey.messagesCount-revealedMessagesCount)
	basesVC2 = append(basesVC2, sp.d, pubKey.h0)

	basesDisclosed := make([]*bls12381.PointG1, 0, 1+revealedMessagesCount)
	exponents := make([]*bls12381.Fr, 0, 1+revealedMessagesCount)

	basesDisclosed = append(basesDisclosed, g1.One())
	exponents = append(exponents, bls12381.NewFr().One())

	revealedMessagesInd := 0

	for i := range pubKey.h {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.h[i])
			exponents = append(exponents, messages[revealedMessagesInd].FR)
			revealedMessagesInd++
		} else {
			basesVC2 = append(basesVC2, pubKey.h[i])
		}
	}

	pr := g1.Zero()

	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := g1.New()
		g1.MulScalar(g, b, frToRepr(s))
		g1.Add(pr, pr, g)
	}

	g1.Neg(pr, pr)

	err := sp.proofVC2.Verify(basesVC2, pr, challenge)
	if err != nil {
		return errors.New("bad signature")
	}

	return nil
}

// ToBytes converts PoKOfSignatureProof to bytes.
func (sp *PoKOfSignatureProof) ToBytes() []byte {
	bytes := make([]byte, 0)

	bytes = append(bytes, g1.ToCompressed(sp.aPrime)...)
	bytes = append(bytes, g1.ToCompressed(sp.aBar)...)
	bytes = append(bytes, g1.ToCompressed(sp.d)...)

	proof1Bytes := sp.proofVC1.ToBytes()
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proof1Bytes)))
	bytes = append(bytes, lenBytes...)
	bytes = append(bytes, proof1Bytes...)

	bytes = append(bytes, sp.proofVC2.ToBytes()...)

	return bytes
}

// ProofG1 is a proof of knowledge of a signature and hidden messages.
type ProofG1 struct {
	commitment *bls12381.PointG1
	responses  []*bls12381.Fr
}

// NewProofG1 creates a new ProofG1.
func NewProofG1(commitment *bls12381.PointG1, responses []*bls12381.Fr) *ProofG1 {
	return &ProofG1{
		commitment: commitment,
		responses:  responses,
	}
}

// Verify verifies the ProofG1.
func (pg1 *ProofG1) Verify(bases []*bls12381.PointG1, commitment *bls12381.PointG1, challenge *bls12381.Fr) error {
	contribution := pg1.getChallengeContribution(bases, commitment, challenge)
	g1.Sub(contribution, contribution, pg1.commitment)

	if !g1.IsZero(contribution) {
		return errors.New("contribution is not zero")
	}

	return nil
}

func (pg1 *ProofG1) getChallengeContribution(bases []*bls12381.PointG1, commitment *bls12381.PointG1,
	challenge *bls12381.Fr) *bls12381.PointG1 {
	points := append(bases, commitment)
	scalars := append(pg1.responses, challenge)

	return sumOfG1Products(points, scalars)
}

// ToBytes converts ProofG1 to bytes.
func (pg1 *ProofG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	commitmentBytes := g1.ToCompressed(pg1.commitment)
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(pg1.responses)))
	bytes = append(bytes, lenBytes...)

	for i := range pg1.responses {
		responseBytes := frToRepr(pg1.responses[i]).ToBytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes
}

// ParseSignatureProof parses a signature proof.
func ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	if len(sigProofBytes) < g1CompressedSize*3 {
		return nil, errors.New("invalid size of signature proof")
	}

	g1Points := make([]*bls12381.PointG1, 3)
	offset := 0

	for i := range g1Points {
		g1Point, err := g1.FromCompressed(sigProofBytes[offset : offset+g1CompressedSize])
		if err != nil {
			return nil, fmt.Errorf("parse G1 point: %w", err)
		}

		g1Points[i] = g1Point
		offset += g1CompressedSize
	}

	proof1BytesLen := int(uint32FromBytes(sigProofBytes[offset : offset+4]))
	offset += 4

	proofVc1, err := ParseProofG1(sigProofBytes[offset : offset+proof1BytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	offset += proof1BytesLen

	proofVc2, err := ParseProofG1(sigProofBytes[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{
		aPrime:   g1Points[0],
		aBar:     g1Points[1],
		d:        g1Points[2],
		proofVC1: proofVc1,
		proofVC2: proofVc2,
	}, nil
}

// ParseProofG1 parses ProofG1 from bytes.
func ParseProofG1(bytes []byte) (*ProofG1, error) {
	if len(bytes) < g1CompressedSize+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	offset := 0

	commitment, err := g1.FromCompressed(bytes[:g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += g1CompressedSize
	length := int(uint32FromBytes(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < g1CompressedSize+4+length*frCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*bls12381.Fr, length)
	for i := 0; i < length; i++ {
		responses[i] = parseFr(bytes[offset : offset+frCompressedSize])
		offset += frCompressedSize
	}

	return NewProofG1(commitment, responses), nil
}
