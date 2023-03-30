/*
SPDX-License-Identifier: Apache-2.0
*/

package bls12381

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestExpandMessageXMD(t *testing.T) {
	t.Run("IRTF H2C draft16 K1 abc", func(t *testing.T) {
		hashFunc := func() hash.Hash {
			h := sha256.New()
			return h
		}
		outCnt := 0x20
		out, err := expandMsgXMD(hashFunc, []byte("abc"), []byte("QUUX-V01-CS02-with-expander-SHA256-128"), outCnt)
		require.NoError(t, err)
		require.Equal(t, len(out), outCnt)
		require.Equal(t, "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615", hex.EncodeToString(out))
	})

	t.Run("IRTF H2C draft16 K1 abcdef0123456789", func(t *testing.T) {
		hashFunc := func() hash.Hash {
			h := sha256.New()
			return h
		}
		outCnt := 0x20
		out, err := expandMsgXMD(hashFunc, []byte("abcdef0123456789"), []byte("QUUX-V01-CS02-with-expander-SHA256-128"), outCnt)
		require.NoError(t, err)
		require.Equal(t, len(out), outCnt)
		require.Equal(t, "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1", hex.EncodeToString(out))
	})
}

func TestExpandMessageXOF(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-expander-SHAKE256")
	t.Run("IRTF H2C draft16 K6 abc", func(t *testing.T) {
		outCnt := 0x20
		out, err := ExpandMsgXOF(sha3.NewShake256(), []byte("abc"), dst, outCnt)
		require.NoError(t, err)
		require.Equal(t, len(out), outCnt)
		require.Equal(t, "b39e493867e2767216792abce1f2676c197c0692aed061560ead251821808e07", hex.EncodeToString(out))
	})

	t.Run("IRTF H2C draft16 K6 abcdef0123456789", func(t *testing.T) {
		outCnt := 0x20
		out, err := ExpandMsgXOF(sha3.NewShake256(), []byte("abcdef0123456789"), dst, outCnt)
		require.NoError(t, err)
		require.Equal(t, len(out), outCnt)
		require.Equal(t, "245389cf44a13f0e70af8665fe5337ec2dcd138890bb7901c4ad9cfceb054b65", hex.EncodeToString(out))
	})
}
