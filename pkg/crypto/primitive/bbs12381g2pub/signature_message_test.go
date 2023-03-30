/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

func TestParseSignatureMessages(t *testing.T) {
	msgs := [][]byte{
		hexToBytes(t, "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		hexToBytes(t, "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"),
		hexToBytes(t, "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"),
		hexToBytes(t, "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943"),
		hexToBytes(t, "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151"),
		hexToBytes(t, "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc"),
		hexToBytes(t, "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2"),
		hexToBytes(t, "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91"),
		hexToBytes(t, "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416"),
		hexToBytes(t, "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
	}

	sc := bbs.ParseSignatureMessages(msgs)

	require.Equal(t,
		hexToBytes(t, "4e67c49cf68df268bca0624880770bb57dbe8460c89883cc0ac496785b68bbe9"), sc[0].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "12d92c990f37ffab1c6ac4b0cd83378ffb8a8610259d62d3b885fc4c1bc50f7f"), sc[1].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "41a157520e8752ca100a365ffde4683fb9610bf105b40933bb98dcacbbd56ace"), sc[2].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "3344daad11febac28f0f8e3740cd2921fd6da18ebc7e9692a8287cedea5f4bf4"), sc[3].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "0407198a8ffc4640b840fc924e5308f405ca86035d05366718aafd0b688876f3"), sc[4].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "1918fa78c85628cb3ac705cc4843197d3fce88c8132d9242d87201e65a4d3743"), sc[5].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "0a272f853369d70526d7bd37281bb87d1c8db7d0975dd833812bb9d264f4b0eb"), sc[6].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "00776f91d1ecb5cc01ffe155ae05efea0b820f3d40bada5142bb852f9922b7e1"), sc[7].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "3902ced42427bca88822f818912d2f4c0d88ba1d1fc7a9b0e2321674a5d53f27"), sc[8].FR.ToBytes())
	require.Equal(t,
		hexToBytes(t, "397864d9292b1f4a5fff5fa33088ed8e1a9ec52346dbd5f66ee0f978bd67595d"), sc[9].FR.ToBytes())
}
