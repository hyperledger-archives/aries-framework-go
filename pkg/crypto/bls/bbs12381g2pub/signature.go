/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"
	"fmt"

	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g2pubs"
)

// Signature defines BLS signature.
type Signature struct {
	Signature *g2pubs.Signature

	E *bls.FR
	S *bls.FR
}

// ParseSignature parses a Signature from bytes.
func ParseSignature(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != bls12381SignatureLen {
		return nil, errors.New("invalid size of signature")
	}

	var sigBytesArr [g1CompressedSize]byte
	copy(sigBytesArr[:], sigBytes[:g1CompressedSize])

	signature, err := g2pubs.DeserializeSignature(sigBytesArr)
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 compressed signature: %w", err)
	}

	e := parseFr(sigBytes[g1CompressedSize : g1CompressedSize+frCompressedSize])
	s := parseFr(sigBytes[g1CompressedSize+frCompressedSize:])

	return &Signature{
		Signature: signature,
		E:         e,
		S:         s,
	}, nil
}

// GetPoint returns G1 point of the Signature.
func (s *Signature) GetPoint() *bls.G1Projective {
	return s.Signature.GetPoint()
}
