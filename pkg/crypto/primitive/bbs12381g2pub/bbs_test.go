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
		"84d9677e651d7e039ff1bd3c6c37a6d465b23ebcc1291cf0082cd94c3971ff2ec64d8ddfd0c2f68d37429f6c751003a7"+
			"5435cae4b55250e5a3e357b7bd52589ff830820cd5e07a6125d846245efacccb"+
			"5814139b8bef5b329b3a269f576565d33bf6254916468f9e997a685ac68508a6")

	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.Verify(nil, messagesBytes, sigBytes, pkBytes)
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
	privateKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")
	header := hexStringToBytesTest(t, "11223344556677889900aabbccddeeff")
	messagesBytes := default10messages(t)

	bls := bbs12381g2pub.New()
	signature, err := bls.Sign(header, messagesBytes, privateKeyBytes)
	require.NoError(t, err)

	expectedSignatureBytes := hexStringToBytesTest(t,
		"9157456791e4f9cae1130372f7cf37709ba661e43df5c23cc1c76be91abff7e2603e2ddaaa71fc42bd6f9d44bd58315b"+
			"09ee5cc4e7614edde358f2c497b6b05c8b118fae3f71a52af482dceffccb3785"+
			"1907573c03d2890dffbd1f660cdf89c425d4e0498bbf73dd96ff15ad9a8b581a")

	require.Equal(t, expectedSignatureBytes, signature)
}

func TestBBSG2Pub_VerifyProof_SeveralDisclosedMessages(t *testing.T) {
	privateKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

	privateKey, err := bbs12381g2pub.UnmarshalPrivateKey(privateKeyBytes)
	require.NoError(t, err)

	pkBytes, err := privateKey.PublicKey().Marshal()
	require.NoError(t, err)

	proofBytes := hexStringToBytesTest(t, "000a0005ab1a7238bc9ba5065c9d1f395720f97b8d68208e89edb1fa8f1cde16c07b7771a46359ef198317ca71cfae5937200485b3e62de95b4d05a95c8d882197c56e582f74b5e6e1e4ae866a93fa13ae32690b8ea1bbbd7f1138f18a750ede1915a6d2898eec5b19028f2765585f36be4f152bd4ac2ad280743bed14ec78e0cdbf80f0547b37b1de62d71144f03e1fdec89b05000000748adcb65ca0ed38b9c6d1649bef5cd942175affdb9c7ad5212b371f0472d39228dc6c220cc80846fb2f44911b7aed2f32000000020910a8400998e7903a401b439d9a84723e46c9f0c03a9949ac9ee2d545caf72a50cd0f2f340a04a22ffbc8c4c6aa15af1ae972c18bbe6b463707836fb08d624089a4b92531729d0ce3f44ca36b47331a4c9a51af11d5b0f9bf4b55d8d09db24c8df59c6ad111ae0f9af56e16681a53df0000000a5916c0c291dc659d25699f2b182e2fbafe091bdf7a0667a4e4f047e80fa3d64214ee7f20d63f31472ec2eeac73ca01e51c2e420f3a26cda4e0cbe82e64f92a62075131c9dfde53d16e8c3e1d0b56bd6ac203f07af450cb94b019c6bb667df2465f9317c9ac178e58f638eb52751638fd54a211ab0ab3aeee8d87a69392de458f6ddb6b9f007589f6bdb5376eeffc4f64f7c7c0c426197be97f4f83a1a6f06ff74473dde98edbb444976ef4083237a859807d1a4c1e94fe68b69609fa00431e4b4622a39bd74791ce4b1f7545291b5ded098a757f680cbe1612312c8f841a8d0b077e5cf3eb5cf85f0ed9a3a061c3aa447c9a6bc87808d3ee1f293d157d1f41f14edd5cd0b1fcb5112d7e09386a276f396d4f31f1660bb65f0206eb92d669d2800f1e0f418be23895ad0cac055f973b50c38d57df54563e5493dd7910308ed9a6") //nolint:lll

	// TODO   "header": "11223344556677889900aabbccddeeff"
	nonce := hexStringToBytesTest(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

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
		proofBytesCopy[23] = 255 - proofBytesCopy[23]

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
	privKeyBytes := hexStringToBytesTest(t, "47d2ede63ab4c329092b342ab526b1079dbc2595897d4f2ab2de4d841cbe7d56")

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

	nonce := hexStringToBytesTest(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
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
