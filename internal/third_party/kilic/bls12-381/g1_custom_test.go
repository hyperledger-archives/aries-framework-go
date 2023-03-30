/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

func TestG1CustomSerialization(t *testing.T) {
	pointG1 := new(PointG1).Zero()

	g := NewG1()

	pointBytes := g.ToBytes(pointG1)
	if len(pointBytes) == 0 {
		t.Fatal("empty bytes")
	}

	pointG1.Set(&PointG1{
		{
			40,
			50,
		},
	})

	pointBytes = g.ToBytes(pointG1)
	if len(pointBytes) == 0 {
		t.Fatal("empty bytes")
	}
}

func TestHashToCurve(t *testing.T) {
	g := NewG1()
	t.Run("hello test", func(t *testing.T) {
		hashFunc := func() hash.Hash {
			// We pass a null key so error is impossible here.
			h, _ := blake2b.New512(nil)

			return h
		}

		curve, err := g.HashToCurveGenericXMD([]byte("hello"),
			[]byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0"),
			hashFunc)

		require.NoError(t, err)
		require.NotEqual(t, 0, len(curve))
	})

	t.Run("IRTF H2C draft16 J91 empty msg", func(t *testing.T) {
		hashFunc := func() hash.Hash {
			h := sha256.New()
			return h
		}

		curve, err := g.HashToCurveGenericXMD([]byte(""),
			[]byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"),
			hashFunc)
		require.NoError(t, err)
		require.Equal(t, ""+ //x and y coordinates
			"052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"+
			"08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
			hex.EncodeToString(NewG1().ToUncompressed(curve)))
	})

	t.Run("IRTF H2C draft16 J91 abc", func(t *testing.T) {
		hashFunc := func() hash.Hash {
			h := sha256.New()
			return h
		}

		curve, err := g.HashToCurveGenericXMD([]byte("abc"),
			[]byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"),
			hashFunc)
		require.NoError(t, err)
		require.Equal(t, ""+ //x and y coordinates
			"03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903"+
			"0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
			hex.EncodeToString(NewG1().ToUncompressed(curve)))
	})
}
