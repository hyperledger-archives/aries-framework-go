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

// BBSG2Pub defines BBS+ signature scheme where public key is a point in the field of G2.
type BBSG2Pub struct {
}

// New creates a new BBSG2Pub.
func New() *BBSG2Pub {
	return &BBSG2Pub{}
}

const (
	// Signature length.
	bls12381SignatureLen = 112

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48

	// Number of bytes in G1 X and Y coordinates.
	g1UncompressedSize = 96

	// Number of bytes in G2 X(a, b) and Y(a, b) coordinates.
	g2UncompressedSize = 192

	// Number of bytes in scalar compressed form.
	frCompressedSize = 32
)

// Verify makes BLS BBS12-381 signature verification.
func (b BBSG2Pub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) error {
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
		messagesFr[i], err = ParseSignatureMessage(messages[i])
		if err != nil {
			return fmt.Errorf("parse signature message: %w", err)
		}
	}

	p1 := signature.GetPoint().ToAffine()
	q1 := bls.G2ProjectiveOne.
		MulFR(signature.E.ToRepr()).
		Add(publicKey.GetPoint())

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
	const basesOffset = 2

	messagesCount := len(messages)

	bases := make([]*bls.G1Projective, messagesCount+basesOffset)
	scalars := make([]*bls.FR, messagesCount+basesOffset)

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
			return nil, fmt.Errorf("create G1 point from hash: %w", err)
		}
	}

	bases[1] = h0
	scalars[1] = s

	for i := 0; i < len(messages); i++ {
		bases[i+basesOffset] = h[i]
		scalars[i+basesOffset] = messages[i].FR
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
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil) //nolint:errcheck
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

	// Here we convert valid bls G1 and G2 points to bls12381 ones using marshalling/unmarshalling,
	// error is not possible.
	//nolint:errcheck
	addPairFunc := func(p *bls.G1Projective, q *bls.G2Projective) {
		bytesG1 := p.ToAffine().SerializeBytes()
		g1, _ := engine.G1.FromUncompressed(bytesG1[:])

		bytesG2 := q.ToAffine().SerializeBytes()
		g2, _ := engine.G2.FromUncompressed(bytesG2[:])

		engine.AddPair(g1, g2)
	}

	addPairFunc(p1, q1)
	addPairFunc(p2, q2)

	return engine.Check()
}

func parseFr(data []byte) (*bls.FR, error) {
	var arr [32]byte

	copy(arr[:], data)

	fr := bls.FRReprToFR(bls.FRReprFromBytes(arr))
	if fr == nil {
		return nil, errors.New("invalid FR")
	}

	return fr, nil
}
