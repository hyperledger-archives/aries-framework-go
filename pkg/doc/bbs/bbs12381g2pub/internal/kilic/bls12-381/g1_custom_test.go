/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"golang.org/x/crypto/blake2b"
	"hash"
	"testing"
)

func TestG1Serialization(t *testing.T) {
	pointG1 := new(PointG1).Zero()

	pointBytes := ToBytes(pointG1)
	if len(pointBytes) == 0 {
		t.Fatal("empty bytes")
	}

	pointG1.Set(&PointG1{
		{
			40,
			50,
		},
	})

	pointBytes = ToBytes(pointG1)
	if len(pointBytes) == 0 {
		t.Fatal("empty bytes")
	}
}

func TestHashToCurve(t *testing.T) {
	hashFunc := func() hash.Hash {
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil)

		return h
	}

	curve, err := HashToCurve([]byte("hello"),
		[]byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0"),
		hashFunc)
	if err != nil {
		t.Fatal(err)
	}

	if len(curve) == 0 {
		t.Fatal("empty curve bytes")
	}
}
