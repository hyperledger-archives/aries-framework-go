/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"encoding/binary"
	"errors"

	bls12381 "github.com/kilic/bls12-381"
)

func uint32ToBytes(value uint32) []byte {
	bytes := make([]byte, 4)

	binary.BigEndian.PutUint32(bytes, value)

	return bytes
}

func uint64ToBytes(value uint64) []byte {
	bytes := make([]byte, 8)

	binary.BigEndian.PutUint64(bytes, value)

	return bytes
}

func uint16FromBytes(bytes []byte) uint16 {
	return binary.BigEndian.Uint16(bytes)
}

func uint32FromBytes(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

func bitvectorToIndexes(data []byte) []int {
	revealedIndexes := make([]int, 0)
	scalar := 0

	for _, v := range data {
		remaining := 8

		for v > 0 {
			revealed := v & 1
			if revealed == 1 {
				revealedIndexes = append(revealedIndexes, scalar)
			}

			v >>= 1
			scalar++
			remaining--
		}

		scalar += remaining
	}

	return revealedIndexes
}

type pokPayload struct {
	messagesCount int
	revealed      []int
}

// nolint:gomnd
func parsePoKPayload(bytes []byte) (*pokPayload, error) {
	if len(bytes) < 2 {
		return nil, errors.New("invalid size of PoK payload")
	}

	messagesCount := int(uint16FromBytes(bytes[0:2]))
	offset := lenInBytes(messagesCount)

	if len(bytes) < offset {
		return nil, errors.New("invalid size of PoK payload")
	}

	revealed := bitvectorToIndexes(reverseBytes(bytes[2:offset]))

	return &pokPayload{
		messagesCount: messagesCount,
		revealed:      revealed,
	}, nil
}

// nolint:gomnd
func (p *pokPayload) toBytes() ([]byte, error) {
	bytes := make([]byte, p.lenInBytes())

	binary.BigEndian.PutUint16(bytes, uint16(p.messagesCount))

	bitvector := bytes[2:]

	for _, r := range p.revealed {
		idx := r / 8
		bit := r % 8

		if len(bitvector) <= idx {
			return nil, errors.New("invalid size of PoK payload")
		}

		bitvector[idx] |= 1 << bit
	}

	reverseBytes(bitvector)

	return bytes, nil
}

func (p *pokPayload) lenInBytes() int {
	return lenInBytes(p.messagesCount)
}

func lenInBytes(messagesCount int) int {
	return 2 + (messagesCount / 8) + 1 //nolint:gomnd
}

func newPoKPayload(messagesCount int, revealed []int) *pokPayload {
	return &pokPayload{
		messagesCount: messagesCount,
		revealed:      revealed,
	}
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func calculateChallenge(aPrime, aBar, d, c1, c2 *bls12381.PointG1,
	msgsMap map[int]*SignatureMessage, msgCnt int, domain *bls12381.Fr, nonce []byte) *bls12381.Fr {
	r := len(msgsMap)
	idxSz := 8

	challengeBytes := g1.ToUncompressed(aPrime)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(aBar)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(d)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(c1)...)
	challengeBytes = append(challengeBytes, g1.ToUncompressed(c2)...)
	challengeBytes = append(challengeBytes, uint64ToBytes(uint64(r))...)

	idxs := make([]byte, r*idxSz)
	msgs := make([]byte, 0)

	for i := 0; i < msgCnt; i++ {
		if m, ok := msgsMap[i]; ok {
			idxs = append(idxs, uint64ToBytes(uint64(i))...)
			msgs = append(msgs, m.FR.ToBytes()...)
		}
	}

	challengeBytes = append(challengeBytes, idxs...)
	challengeBytes = append(challengeBytes, msgs...)
	challengeBytes = append(challengeBytes, domain.ToBytes()...)
	proofNonce := ParseProofNonce(nonce)
	proofNonceBytes := proofNonce.ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)

	challenge := Hash2scalar(challengeBytes)

	return challenge
}
