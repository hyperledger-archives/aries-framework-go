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

func TestHash2Scalars(t *testing.T) {
	msg := hexToBytes(t, "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")

	t.Run("single", func(t *testing.T) {
		sc := bbs.Hash2scalar(msg).ToBytes()
		require.Equal(t, hexToBytes(t, "260cab748e24ccc2bbd66f5b834d692622fa131f5ce898fa57217434c9ed14fa"), sc)
	})

	t.Run("multiple", func(t *testing.T) {
		sc := bbs.Hash2scalars(msg, 10)
		require.Equal(t, hexToBytes(t, "5c6e62607c16397ee6d9624673be9a7ddacbc7b7dd290bdb853cf4c74a34de0a"), sc[0].ToBytes())
		require.Equal(t, hexToBytes(t, "2a3524e43413a5d1b34c4c8ed119c4c5a2f9b84392ff0fea0d34e1be44ceafbc"), sc[1].ToBytes())
		require.Equal(t, hexToBytes(t, "4b649b82eed1e62117d91cd8d22438e72f3f931a0f8ad683d1ade253333c472a"), sc[2].ToBytes())
		require.Equal(t, hexToBytes(t, "64338965f1d37d17a14b6f431128c0d41a7c3924a5f484c282d20205afdfdb8f"), sc[3].ToBytes())
		require.Equal(t, hexToBytes(t, "0dfe01c01ff8654e43a611b76aaf4faec618a50d85d34f7cc89879b179bde3d5"), sc[4].ToBytes())
		require.Equal(t, hexToBytes(t, "6b6935016e64791f5d719f8206284fbe27dbb8efffb4141512c3fbfbfa861a0f"), sc[5].ToBytes())
		require.Equal(t, hexToBytes(t, "0dfe13f85a36df5ebfe0efac3759becfcc2a18b134fd22485c151db85f981342"), sc[6].ToBytes())
		require.Equal(t, hexToBytes(t, "5071751012c142046e7c3508decb0b7ba9a453d06ce7787189f4d93a821d538e"), sc[7].ToBytes())
		require.Equal(t, hexToBytes(t, "5cdae3304e745553a75134d914db5b282cc62d295e3ed176fb12f792919fd85e"), sc[8].ToBytes())
		require.Equal(t, hexToBytes(t, "32b67dfbba729831798279071a39021b66fd68ee2e68684a0f6901cd6fcb8256"), sc[9].ToBytes())
	})
}
