/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"crypto/rand"

	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"

	bls12381intern "github.com/hyperledger/aries-framework-go/internal/third_party/kilic/bls12-381"
)

const (
	k         = 128
	h2sDST    = csID + "H2S_"
	expandLen = (logR2 + k + 7) / 8 //nolint:gomnd
)

func parseFr(data []byte) *bls12381.Fr {
	return bls12381.NewFr().FromBytes(data)
}

func f2192() *bls12381.Fr {
	return &bls12381.Fr{0, 0, 0, 1}
}

func frFromOKM(message []byte) *bls12381.Fr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message)
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := bls12381.NewFr().FromBytes(append(emptyEightBytes, okm[:okmMiddle]...))
	elm.Mul(elm, f2192())

	fr := bls12381.NewFr().FromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm.Add(elm, fr)

	return elm
}

func frToRepr(fr *bls12381.Fr) *bls12381.Fr {
	frRepr := bls12381.NewFr()
	frRepr.Mul(fr, &bls12381.Fr{1})

	return frRepr
}

func createRandSignatureFr() *bls12381.Fr {
	fr, _ := bls12381.NewFr().Rand(rand.Reader) //nolint:errcheck

	return frToRepr(fr)
}

// Hash2scalar convert message represented in bytes to Fr.
func Hash2scalar(message []byte) *bls12381.Fr {
	return Hash2scalars(message, 1)[0]
}

// Hash2scalars convert messages represented in bytes to Fr.
func Hash2scalars(msg []byte, cnt int) []*bls12381.Fr {
	return hash2scalars(msg, []byte(h2sDST), cnt)
}

func hash2scalars(msg, dst []byte, cnt int) []*bls12381.Fr {
	bufLen := cnt * expandLen
	msgLen := len(msg)
	roundSz := 1
	msgLenSz := 4

	msgExt := make([]byte, msgLen+roundSz+msgLenSz)
	// msgExt is a concatenation of: msg || I2OSP(round, 1) || I2OSP(cnt, 4)
	copy(msgExt, msg)
	copy(msgExt[msgLen+1:], uint32ToBytes(uint32(cnt)))

	out := make([]*bls12381.Fr, cnt)

	for round, completed := byte(0), false; !completed; {
		msgExt[msgLen] = round
		buf, _ := bls12381intern.ExpandMsgXOF(sha3.NewShake256(), msgExt, dst, bufLen) //nolint:errcheck

		ok := true
		for i := 0; i < cnt && ok; i++ {
			out[i] = bls12381.NewFr().FromBytes(buf[i*expandLen : (i+1)*expandLen])
			ok = !out[i].IsZero()
		}

		completed = ok
	}

	return out
}
