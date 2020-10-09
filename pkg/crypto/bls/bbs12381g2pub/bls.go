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
	"github.com/phoreproject/bls/g2pubs"
	"golang.org/x/crypto/blake2b"
)

type BlsG2Pub struct {
}

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
	// todo remove magic numbers
	if len(pubKeyBytes) != bls12381G2PublicKeyLen {
		return errors.New("invalid size of public key")
	}

	if len(sigBytes) != bls12381SignatureLen {
		return errors.New("invalid size of signature")
	}

	var pkBytesArr [bls12381G2PublicKeyLen]byte
	copy(pkBytesArr[:], pubKeyBytes[:bls12381G2PublicKeyLen])

	publicKey, err := g2pubs.DeserializePublicKey(pkBytesArr)
	if err != nil {
		return fmt.Errorf("deserialize public key: %w", err)
	}

	var sigBytesArr [g1CompressedSize]byte
	copy(sigBytesArr[:], sigBytes[:g1CompressedSize])

	signature, err := g2pubs.DeserializeSignature(sigBytesArr)
	if err != nil {
		return fmt.Errorf("deserialize signature: %w", err)
	}

	e := parseFr(sigBytes[g1CompressedSize : g1CompressedSize+frCompressedSize])
	s := parseFr(sigBytes[g1CompressedSize+frCompressedSize:])

	messagesFr := make([]*bls.FR, len(messages))
	for i := range messages {
		messagesFr[i] = messageToFr(messages[i])
	}

	p1 := signature.GetPoint().ToAffine()

	q1 := bls.G2ProjectiveOne
	q1 = q1.MulFR(e.ToRepr())
	q1 = q1.Add(publicKey.GetPoint())
	p2 := getB(s, messagesFr, publicKey)

	if CompareTwoPairings(p1.ToProjective(), q1, p2.ToProjective(), bls.G2ProjectiveOne) {
		return nil
	}

	return errors.New("BLS12-381: invalid signature")
}

func parseFr(data []byte) *bls.FR {
	var arr [32]byte
	copy(arr[:], data)

	return bls.FRReprToFR(bls.FRReprFromBytes(arr))
}

func messageToFr(message []byte) *bls.FR {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)
	h, _ := blake2b.New384(nil)
	_, _ = h.Write(message)
	okm := h.Sum(nil)

	elm := parseFr(append(make([]byte, eightBytes, eightBytes), okm[:okmMiddle]...))
	elm.MulAssign(f2192())
	elm.AddAssign(parseFr(append(make([]byte, eightBytes, eightBytes), okm[okmMiddle:]...)))

	return elm
}

func f2192() *bls.FR {
	return bls.NewFr(&bls.FRRepr{
		0x59476ebc41b4528f,
		0xc5a30cb243fcc152,
		0x2b34e63940ccbd72,
		0x1e179025ca247088})
}

func getB(s *bls.FR, messages []*bls.FR, key *g2pubs.PublicKey) *bls.G1Affine {
	messagesCount := len(messages)

	bases := make([]*bls.G1Projective, messagesCount+2)
	scalars := make([]*bls.FR, messagesCount+2)

	bases[0] = bls.G1AffineOne.ToProjective()
	scalars[0] = bls.FRReprToFR(bls.NewFRRepr(1))

	offset := g2UncompressedSize + 1

	data := calcData(key, messagesCount)

	h0, err := hashToG1(data)
	if err != nil {
		panic(err)
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
			panic(err)
		}
	}

	bases[1] = h0
	scalars[1] = s

	for i := 0; i < len(messages); i++ {
		bases[i+2] = h[i]
		scalars[i+2] = messages[i]
	}

	res := bls.G1ProjectiveZero

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i].ToRepr()

		g := b.MulFR(s)
		res = res.Add(g)
	}
	res.NegAssign()

	return res.ToAffine()
}

func calcData(key *g2pubs.PublicKey, messagesCount int) []byte {
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

func CompareTwoPairings(p1 *bls.G1Projective, q1 *bls.G2Projective, p2 *bls.G1Projective, q2 *bls.G2Projective) bool {
	engine := bls12381.NewEngine()

	bytesG1 := p1.ToAffine().SerializeBytes()
	a1, err := engine.G1.FromUncompressed(bytesG1[:])
	if err != nil {
		panic(err)
	}

	bytesG2 := q1.ToAffine().SerializeBytes()
	a2, err := engine.G2.FromUncompressed(bytesG2[:])
	if err != nil {
		panic(err)
	}

	bytesG1 = p2.ToAffine().SerializeBytes()
	b, err := engine.G1.FromUncompressed(bytesG1[:])
	if err != nil {
		panic(err)
	}

	bytesG2 = q2.ToAffine().SerializeBytes()
	g2, err := engine.G2.FromUncompressed(bytesG2[:])
	if err != nil {
		panic(err)
	}

	engine.AddPair(a1, a2)
	engine.AddPair(b, g2)

	return engine.Check()
}
