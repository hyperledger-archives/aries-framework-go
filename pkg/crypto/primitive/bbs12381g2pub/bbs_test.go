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
	privateKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privateKey, err := bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	pkBytes, err := privateKey.PublicKey().Marshal()
	require.NoError(t, err)

	sigBytes := hexStringToBytesTest(t,
		"836370c0f9fee53a4518e3294d2cd9880e9ced5a92fd21f20af898cf76c43a1fa88b3b8a0347313b83cb2f52055c3b56"+
			"24f8ea83101ff3429b07708c790975a43a1893fa848e1ffec1ab97c61196823d"+
			"28c3baa5900943929f3b0fdf36665fa43db9ee82dd855551bb9e7aaa6cc5c764")

	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.Verify(messagesBytes, sigBytes, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// swap messages order
		invalidMessagesBytes := make([][]byte, 10)
		copy(invalidMessagesBytes, messagesBytes)
		invalidMessagesBytes[0] = invalidMessagesBytes[1]

		err = bls.Verify(invalidMessagesBytes, sigBytes, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "invalid BLS12-381 signature")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.Verify(messagesBytes, sigBytes, []byte("invalid"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")

		pkBytesInvalid := make([]byte, len(pkBytes))

		_, err = rand.Read(pkBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(messagesBytes, sigBytes, pkBytesInvalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse public key: deserialize public key")
	})

	t.Run("invalid input signature", func(t *testing.T) {
		err = bls.Verify(messagesBytes, []byte("invalid"), pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature: invalid size of signature")

		sigBytesInvalid := make([]byte, len(sigBytes))

		_, err = rand.Read(sigBytesInvalid)
		require.NoError(t, err)

		err = bls.Verify(messagesBytes, sigBytesInvalid, pkBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse signature: deserialize G1 compressed signature")
	})
}

func TestBBSG2Pub_SignWithKeyPair(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	bls := bbs12381g2pub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	signatureBytes, err := bls.SignWithKey(messagesBytes, privKey)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
}

func TestBBSG2Pub_Sign(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	bls := bbs12381g2pub.New()

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	// invalid private key bytes
	signatureBytes, err = bls.Sign(messagesBytes, []byte("invalid"))
	require.Error(t, err)
	require.EqualError(t, err, "unmarshal private key: invalid size of private key")
	require.Nil(t, signatureBytes)

	// at least one message must be passed
	signatureBytes, err = bls.Sign([][]byte{}, privKeyBytes)
	require.Error(t, err)
	require.EqualError(t, err, "messages are not defined")
	require.Nil(t, signatureBytes)
}

func TestBBSG2Pub_SignWithPredefinedKeys(t *testing.T) {
	privateKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	// TODO   "header": "11223344556677889900aabbccddeeff"

	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()
	signature, err := bls.Sign(messagesBytes, privateKeyBytes)
	require.NoError(t, err)

	expectedSignatureBytes := hexStringToBytesTest(t,
		"836370c0f9fee53a4518e3294d2cd9880e9ced5a92fd21f20af898cf76c43a1fa88b3b8a0347313b83cb2f52055c3b56"+
			"24f8ea83101ff3429b07708c790975a43a1893fa848e1ffec1ab97c61196823d"+
			"28c3baa5900943929f3b0fdf36665fa43db9ee82dd855551bb9e7aaa6cc5c764")
	// TODO signature defined in the spec
	// "9157456791e4f9cae1130372f7cf37709ba661e43df5c23cc1c76be91abff7e2603e2ddaaa71fc42bd6f9d44bd58315b"+
	// "09ee5cc4e7614edde358f2c497b6b05c8b118fae3f71a52af482dceffccb3785"+
	// "1907573c03d2890dffbd1f660cdf89c425d4e0498bbf73dd96ff15ad9a8b581a")

	require.Equal(t, expectedSignatureBytes, signature)
}

func TestBBSG2Pub_VerifyProof_SeveralDisclosedMessages(t *testing.T) {
	privateKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privateKey, err := bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	pkBytes, err := privateKey.PublicKey().Marshal()
	require.NoError(t, err)

	proofBytes := hexStringToBytesTest(t, "000a000589bb7f2662f787a87e205fd2f0b6b130e26040cf709359e5cb734b545f461c7fdd8cc35ef85ade32efa449d8c6712a7690f205b468dac30eae9e28da3cea5372520fac0f2a80c16aec7e420ed3c04ec5cca8cb32bfa91083fc106129a9035c3088cc8cdbe6ed083962e7e34562928734d9cec9bcb0ad9355116709f844402cbfe8ad0b542199b5b3adf5132cc96d594700000074943803ea10df094657ac0277aa9ae8738bade0898163c22bce7fd9d986ec07ae58920888026df450dfe2fe46f65ef290000000026e3bdf3df40df5885b9962cacacae6c7687f04c2c673a1f23cb73b067461ca9d646c1616afde5cd0911a752e4dc45dd493b7b0faa695688c3cf387edd3d9d48891e949783029b20e4c5a4480f64238a680f5e48dffcffd61dcd08a2e354634ac73cdc7612c2adfabfaef736f7288da1e0000000a5ed77af0675487ebbdaaa73ebc0d2235804928dd603326878aedd9714be745bb187d6188b10a42ea38da50a76d0c3308e8f101c0ea71f5caa99d0ddca929252328904bd2c92bd1ca9fdff5197c8fb66ff3323aae22180ccd672bb92086bc8b57496d36667bf9ed67a63763d75d3e71fcda6ff5e15399dda6432558238090cfea4da5c52986a874d4da93c231b78365ccb0370c3fb8cf10de36726fc283151d8954e8594209733e772226424b619d3f692236b65f244c121d8e11415d7f9e245015341d76585f3e3257304b0b894ac6fa3357c500da7c8aa15dfa3c1b7cca1da0375e63c9f6b062b02fdce1860e216b5fbd86bd5a3c5838a8cb87467b06f07c1360ba28286e40bdf07c954685c6dd2f64b9ae986fd3079834148eea0a44869b8d71421ae35157f0641db09bf7728606e7d7e6f6cf133a3e2db80940638f39be61") //nolint:lll

	// TODO   "header": "11223344556677889900aabbccddeeff"
	nonce := hexStringToBytesTest(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

	messagesBytes := default10messages(t)
	revealedMessagesBytes := [][]byte{messagesBytes[0], messagesBytes[2]}

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid size of signature proof payload", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, []byte("?"), nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of PoK payload")
	})

	t.Run("invalid size of signature proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, 5)

		copy(proofBytesCopy, proofBytes)

		err = bls.VerifyProof(revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: invalid size of signature proof")
	})

	t.Run("invalid proof", func(t *testing.T) {
		proofBytesCopy := make([]byte, len(proofBytes))

		copy(proofBytesCopy, proofBytes)
		proofBytesCopy[21] = 255 - proofBytesCopy[21]

		err = bls.VerifyProof(revealedMessagesBytes, proofBytesCopy, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "parse signature proof: parse G1 point: point is not on curve")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, []byte("invalid public key"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")
	})
}

func TestBBSG2Pub_DeriveProof(t *testing.T) {
	privKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privKey, err := bbs12381g2pub.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)

	pubKey := privKey.PublicKey()

	messagesBytes := default10messages(t)
	bls := bbs12381g2pub.New()

	signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	nonce := hexStringToBytesTest(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	revealedIndexes := []int{0, 2}
	proofBytes, err := bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
	require.NoError(t, err)
	require.NotEmpty(t, proofBytes)

	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
	}

	require.NoError(t, bls.VerifyProof(revealedMessages, proofBytes, nonce, pubKeyBytes))

	t.Run("DeriveProof with revealedIndexes larger than revealedMessages count", func(t *testing.T) {
		revealedIndexes = []int{0, 2, 4, 7, 9, 11}
		_, err = bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
		require.EqualError(t, err, "init proof of knowledge signature: "+
			"invalid revealed index: requested index 11 is larger than 10 messages count")
	})
}

func default10messages(t *testing.T) [][]byte {
	messagesBytes := [][]byte{
		hexStringToBytesTest(t, "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
		hexStringToBytesTest(t, "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"),
		hexStringToBytesTest(t, "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"),
		hexStringToBytesTest(t, "ac55fb33a75909edac8994829b250779298aa75d69324a365733f16c333fa943"),
		hexStringToBytesTest(t, "d183ddc6e2665aa4e2f088af9297b78c0d22b4290273db637ed33ff5cf703151"),
		hexStringToBytesTest(t, "515ae153e22aae04ad16f759e07237b43022cb1ced4c176e0999c6a8ba5817cc"),
		hexStringToBytesTest(t, "496694774c5604ab1b2544eababcf0f53278ff5040c1e77c811656e8220417a2"),
		hexStringToBytesTest(t, "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c23364568523f8b91"),
		hexStringToBytesTest(t, "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b7320912416"),
		hexStringToBytesTest(t, "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"),
	}

	return messagesBytes
}

func hexStringToBytesTest(t *testing.T, msg string) []byte {
	bytes, err := hex.DecodeString(msg)
	require.NoError(t, err)

	return bytes
}
