/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

// Signature defines BLS signature.
type Signature struct {
	A *bls12381.PointG1
	E *bls12381.Fr
	S *bls12381.Fr
}

// ParseSignature parses a Signature from bytes.
func ParseSignature(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != bls12381SignatureLen {
		return nil, errors.New("invalid size of signature")
	}

	g1 := bls12381.NewG1()

	pointG1, err := g1.FromCompressed(sigBytes[:g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 compressed signature: %w", err)
	}

	e := parseFr(sigBytes[g1CompressedSize : g1CompressedSize+frCompressedSize])
	s := parseFr(sigBytes[g1CompressedSize+frCompressedSize:])

	return &Signature{
		A: pointG1,
		E: e,
		S: s,
	}, nil
}

// ToBytes converts signature to bytes using compression of G1 point and E, S FR points.
func (s *Signature) ToBytes() ([]byte, error) {
	bytes := make([]byte, bls12381SignatureLen)

	g1 := bls12381.NewG1()

	copy(bytes, g1.ToCompressed(s.A))
	copy(bytes[g1CompressedSize:g1CompressedSize+frCompressedSize], s.E.RedToBytes())
	copy(bytes[g1CompressedSize+frCompressedSize:], s.S.RedToBytes())

	return bytes, nil
}
