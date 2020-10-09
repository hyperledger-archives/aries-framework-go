/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	bls12381 "github.com/kilic/bls12-381"
	"github.com/phoreproject/bls"
	"golang.org/x/crypto/blake2b"
)

// BlsG2Pub defines BBS+ signature scheme where public key is a point in the field of G2.
type BlsG2Pub struct {
}

// NewBlsG2Pub creates a new BlsG2Pub.
func NewBlsG2Pub() *BlsG2Pub {
	return &BlsG2Pub{}
}

const (
	// Signature length.
	bls12381SignatureLen = 112

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48

	// Number of bytes in G1 X and Y coordinates
	g1UncompressedSize = 96

	// Number of bytes in G2 X(a, b) and Y(a, b) coordinates
	g2UncompressedSize = 192

	// Number of bytes in scalar compressed form.
	frCompressedSize = 32
)

// Verify makes BLS BBS12-381 signature verification.
func (b BlsG2Pub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) error {
	signature, err := ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	publicKey, err := ParsePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	messagesFr := make([]*SignatureMessage, len(messages))
	for i := range messages {
		messagesFr[i] = NewSignatureMessage(messages[i])
	}

	p1 := signature.GetPoint().ToAffine()

	q1 := bls.G2ProjectiveOne
	q1 = q1.MulFR(signature.E.ToRepr())
	q1 = q1.Add(publicKey.GetPoint())

	p2, err := getB(signature.S, messagesFr, publicKey)
	if err != nil {
		return fmt.Errorf("get B point: %w", err)
	}

	if compareTwoPairings(p1.ToProjective(), q1, p2.ToProjective(), bls.G2ProjectiveOne) {
		return nil
	}

	return errors.New("BLS12-381: invalid signature")
}

func getB(s *bls.FR, messages []*SignatureMessage, key *PublicKey) (*bls.G1Affine, error) {
	messagesCount := len(messages)

	bases := make([]*bls.G1Projective, messagesCount+2)
	scalars := make([]*bls.FR, messagesCount+2)

	bases[0] = bls.G1AffineOne.ToProjective()
	scalars[0] = bls.FRReprToFR(bls.NewFRRepr(1))

	offset := g2UncompressedSize + 1

	data := calcData(key, messagesCount)

	h0, err := hashToG1(data)
	if err != nil {
		return nil, fmt.Errorf("create G1 point from hash")
	}

	h := make([]*bls.G1Projective, messagesCount)
	for i := 1; i <= messagesCount; i++ {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		iBytes := uint32ToBytes(uint32(i))

		for j := 0; j < len(iBytes); j++ {
			dataCopy[j+offset] = iBytes[j]
		}

		h[i-1], err = hashToG1(dataCopy)
		if err != nil {
			return nil, fmt.Errorf("create G1 point from hash")
		}
	}

	bases[1] = h0
	scalars[1] = s

	for i := 0; i < len(messages); i++ {
		bases[i+2] = h[i]
		scalars[i+2] = messages[i].FR
	}

	res := bls.G1ProjectiveZero

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i].ToRepr()

		g := b.MulFR(s)
		res = res.Add(g)
	}

	res.NegAssign()

	return res.ToAffine(), nil
}

func calcData(key *PublicKey, messagesCount int) []byte {
	keyBytes := key.GetPoint().ToAffine().SerializeBytes()
	data := keyBytes[:]

	data = append(data, 0, 0, 0, 0, 0, 0)

	mcBytes := uint32ToBytes(uint32(messagesCount))

	data = append(data, mcBytes...)

	return data
}

func uint32ToBytes(value uint32) []byte {
	bytes := make([]byte, 4)

	binary.BigEndian.PutUint32(bytes, value)

	return bytes
}

func hashToG1(data []byte) (*bls.G1Projective, error) {
	dstG1 := []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")

	newBlake2b := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}

	g1 := bls12381.NewG1()

	p0, err := g1.HashToCurve(newBlake2b, data, dstG1)
	if err != nil {
		return nil, fmt.Errorf("hash to curve: %w", err)
	}

	p0Bytes := g1.ToUncompressed(p0)

	var p0BytesArr [g1UncompressedSize]byte
	copy(p0BytesArr[:], p0Bytes)

	var p0Bls bls.G1Affine
	p0Bls.SetRawBytes(p0BytesArr)

	return p0Bls.ToProjective(), nil
}

func compareTwoPairings(p1 *bls.G1Projective, q1 *bls.G2Projective, p2 *bls.G1Projective, q2 *bls.G2Projective) bool {
	engine := bls12381.NewEngine()

	bytesG1 := p1.ToAffine().SerializeBytes()
	a1, _ := engine.G1.FromUncompressed(bytesG1[:])

	bytesG2 := q1.ToAffine().SerializeBytes()
	a2, _ := engine.G2.FromUncompressed(bytesG2[:])

	bytesG1 = p2.ToAffine().SerializeBytes()
	b, _ := engine.G1.FromUncompressed(bytesG1[:])

	bytesG2 = q2.ToAffine().SerializeBytes()
	g2, _ := engine.G2.FromUncompressed(bytesG2[:])

	engine.AddPair(a1, a2)
	engine.AddPair(b, g2)

	return engine.Check()
}
