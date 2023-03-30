/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

func TestBlsG2Pub_Verify(t *testing.T) {
	privateKeyBytes := hexToBytes(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privateKey, err := bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	pkBytes, err := privateKey.PublicKey().Marshal()
	require.NoError(t, err)

	sigBytes := hexToBytes(t,
		"9157456791e4f9cae1130372f7cf37709ba661e43df5c23cc1c76be91abff7e2603e2ddaaa71fc42bd6f9d44bd58315b"+
			"09ee5cc4e7614edde358f2c497b6b05c8b118fae3f71a52af482dceffccb3785"+
			"1907573c03d2890dffbd1f660cdf89c425d4e0498bbf73dd96ff15ad9a8b581a")
	header := hexToBytes(t, "11223344556677889900aabbccddeeff")
	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.Verify(header, messagesBytes, sigBytes, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// swap messages order
		invalidMessagesBytes := make([][]byte, 10)
		copy(invalidMessagesBytes, messagesBytes)
		invalidMessagesBytes[0] = invalidMessagesBytes[1]

		err = bls.Verify(nil, invalidMessagesBytes, sigBytes, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "invalid BLS12-381 signature")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.Verify(nil, messagesBytes, sigBytes, []byte("invalid"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")

		pkBytesInvalid := make([]byte, len(pkBytes))

		_, err = rand.Read(pkBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(nil, messagesBytes, sigBytes, pkBytesInvalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse public key: deserialize public key")
	})

	t.Run("invalid input signature", func(t *testing.T) {
		err = bls.Verify(nil, messagesBytes, []byte("invalid"), pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature: invalid size of signature")

		sigBytesInvalid := make([]byte, len(sigBytes))

		_, err = rand.Read(sigBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(nil, messagesBytes, sigBytesInvalid, pkBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse signature: deserialize G1 compressed signature")
	})
}

func TestBBSG2Pub_SignWithKeyPair(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	bls := bbs12381g2pub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	signatureBytes, err := bls.SignWithKey(nil, messagesBytes, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(nil, messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBBSG2Pub_Sign(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	bls := bbs12381g2pub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := bls.Sign(nil, messagesBytes, privKeyBytes)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(nil, messagesBytes, signatureBytes, pubKeyBytes))

	// invalid private key bytes
	signatureBytes, err = bls.Sign(nil, messagesBytes, []byte("invalid"))
	require.Error(t, err)
	require.EqualError(t, err, "unmarshal private key: invalid size of private key")
	require.Nil(t, signatureBytes)

	// at least one message must be passed
	signatureBytes, err = bls.Sign(nil, [][]byte{}, privKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "messages are not defined")
	require.Nil(t, signatureBytes)
}

func TestBBSG2Pub_SignWithPredefinedKeys(t *testing.T) {
	privateKeyBytes := hexToBytes(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
	header := hexToBytes(t, "11223344556677889900aabbccddeeff")
	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()
	signature, err := bls.Sign(header, messagesBytes, privateKeyBytes)
	require.NoError(t, err)

	expectedSignatureBytes := hexToBytes(t,
		"9157456791e4f9cae1130372f7cf37709ba661e43df5c23cc1c76be91abff7e2603e2ddaaa71fc42bd6f9d44bd58315b"+
			"09ee5cc4e7614edde358f2c497b6b05c8b118fae3f71a52af482dceffccb3785"+
			"1907573c03d2890dffbd1f660cdf89c425d4e0498bbf73dd96ff15ad9a8b581a")

	require.Equal(t, expectedSignatureBytes, signature)
}

func TestBBSG2Pub_VerifyProof_SeveralDisclosedMessages(t *testing.T) {
	privateKeyBytes := hexToBytes(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privateKey, err := bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	pkBytes, err := privateKey.PublicKey().Marshal()
	require.NoError(t, err)

	proofBytes := hexToBytes(t, "000a0005b309e66b61ed40151fe80418c2a603ac98ba5a41348daa5ff8452f8d1c3540e627d1d455cc21e416508566f2ad425ecb8e1502e60fb0b4229ea355768725f249ddd96d16aac62317932d7249cd672780518d361956cadde8113304136cba7de696a928df91d8cd4b839c4539fadfb69eaa7fb06f9383df5e71a63313f595a998052e2c5f0f8041b5fdeaa96587d8365f000000748b822f236fbe22a18573db03f7b7867925e25d765f5b3689a480ae429f7bc93b5e7705b19f03ab752d5d8f40f2179f4e0000000206b4f1e7ac8f6342a3f21fbc8f73689d9020b43749c5b59c08019c009506b3fa7293bf6163a59f207b5bddd63520c24186d294169118757f90adbd00c277f911881f03648d511521053c722b69cb4e9901b0c9e5ec1a2b8dc7effcb2cc9551d2c62e908a7906a19e252b9dc9deb435e30000000a1da464bde0b8b36051d9dafe48478fb07c66d809cb01f5ff1af65ddea5926ae25f7eeb0fc7abe707313cd88a82f338ff9bfa6e66438cb07cae7bbc2539a234fa5abde85f4157c27a5e4bb3f91f71e5ba3218ff6a442bb346a6b25cb4f22f7b346b9a713272d5b47740b12f23e8bf2c28ed396b95c94352cfdc6e217fd92d19671ab662782134a08463c3ad2fd45942f980ada1a0e507283d4c5a650c82a818f86f3260817ff2866634485ee4ca5b5ee530e40c7bfbb18165bcd558a8f8e5f8ef257c733a3f0c1eb7a5d5a7be14a6ef5dc897c77ad5e05e830a0e180608aa88fe0d4963a99d88008fe7d9ff77005ba59a3b667d9d17a95510095d631a1e61be812540857d411593c464a0d403713daa9e377d58867dfbb315d09b8eecd2aa58f72de98c306484f88a325ba57b33fd1636c713c340147c55e6c932b394afea1567") //nolint:lll

	// TODO   "header": "11223344556677889900aabbccddeeff"
	nonce := hexToBytes(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

	messagesBytes := default10messages(t)
	revealedMessagesBytes := [][]byte{messagesBytes[0], messagesBytes[2]}

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.VerifyProof(nil, revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid size of signature proof payload", func(t *testing.T) {
		err = bls.VerifyProof(nil, revealedMessagesBytes, []byte("?"), nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of PoK payload")
	})

	t.Run("invalid size of signature proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, 5)

		copy(proofBytesCopy, proofBytes)

		err = bls.VerifyProof(nil, revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of signature proof")
	})

	t.Run("invalid proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, len(proofBytes))

		copy(proofBytesCopy, proofBytes)
		proofBytesCopy[21] = 255 - proofBytesCopy[21]

		err = bls.VerifyProof(nil, revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: parse G1 point: point is not on curve")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.VerifyProof(nil, revealedMessagesBytes, proofBytes, nonce, []byte("invalid public key"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")
	})
}

func TestBBSG2Pub_DeriveProof(t *testing.T) {
	privKeyBytes := hexToBytes(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)

	pubKey := privKey.PublicKey()

	messagesBytes := default10messages(t)
	bls := bbs12381g2pub.New()

	signatureBytes, err := bls.Sign(nil, messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(nil, messagesBytes, signatureBytes, pubKeyBytes))

	nonce := hexToBytes(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 2}
	proofBytes, err := bls.DeriveProof(nil, messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
	require.NoError(t, err)
	require.NotEmpty(t, proofBytes)

	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
	}

	require.NoError(t, bls.VerifyProof(nil, revealedMessages, proofBytes, nonce, pubKeyBytes))

	t.Run("DeriveProof with revealedIndexes larger than revealedMessages count", func(t *testing.T) {
		revealedIndexes = []int{0, 2, 4, 7, 9, 11}
		_, err = bls.DeriveProof(nil, messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
		require.EqualError(t, err, "init proof of knowledge signature: "+
			"invalid revealed index: requested index 11 is larger than 10 messages count")
	})
}

func default10messages(t *testing.T) [][]byte {
	messagesBytes := [][]byte{
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

	return messagesBytes
}

func hexToBytes(t *testing.T, msg string) []byte {
	bytes, err := hex.DecodeString(msg)
	require.NoError(t, err)

	return bytes
}
