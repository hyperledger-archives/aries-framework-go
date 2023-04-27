/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

//nolint:lll
func TestBlsG2Pub_Verify(t *testing.T) {
	pkBase64 := "lOpN7uGZWivVIjs0325N/V0dAhoPomrgfXVpg7pZNdRWwFwJDVxoE7TvRyOx/Qr7GMtShNuS2Px/oScD+SMf08t8eAO78QRNErPzwNpfkP4ppcSTShStFDfFbsv9L9yb"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	sigBase64 := "hPbLkeMZZ6KKzkjWoTVHeMeuLJfYWjmdAU1Vg5fZ/VZnIXxxeXBB+q0/EL8XQmWkOMMwEGA/D2dCb4MDuntKZpvHEHlvaFR6l1A4bYj0t2Jd6bYwGwCwirNbmSeIoEmJeRzJ1cSvsL+jxvLixdDPnw=="
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	require.NoError(t, err)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.Verify(messagesBytes, sigBytes, pkBytes)
		require.NoError(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		// swap messages order
		invalidMessagesBytes := [][]byte{[]byte("message2"), []byte("message1")}

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

//nolint:lll
func TestBBSG2Pub_VerifyProof(t *testing.T) {
	pkBase64 := "sVEbbh9jDPGSBK/oT/EeXQwFvNuC+47rgq9cxXKrwo6G7k4JOY/vEcfgZw9Vf/TpArbIdIAJCFMDyTd7l2atS5zExAKX0B/9Z3E/mgIZeQJ81iZ/1HUnUCT2Om239KFx"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	proofBase64 := "AAIBiN4EL9psRsIUlwQah7a5VROD369PPt09Z+jfzamP+/114a5RfWVMju3NCUl2Yv6ahyIdHGdEfxhC985ShlGQrRPLa+crFRiu2pfnAk+L6QMNooVMQhzJc2yYgktHen4QhsKV3IGoRRUs42zqPTP3BdqIPQeLgjDVi1d1LXEnP+WFQGEQmTKWTja4u1MsERdmAAAAdIb6HuFznhE3OByXN0Xp3E4hWQlocCdpExyNlSLh3LxK5duCI/WMM7ETTNS0Ozxe3gAAAAIuALkiwplgKW6YmvrEcllWSkG3H+uHEZzZGL6wq6Ac0SuktQ4n84tZPtMtR9vC1Rsu8f7Kwtbq1Kv4v02ct9cvj7LGcitzg3u/ZO516qLz+iitKeGeJhtFB8ggALcJOEsebPFl12cYwkieBbIHCBt4AAAAAxgEHt3iqKIyIQbTYJvtrMjGjT4zuimiZbtE3VXnqFmGaxVTeR7dh89PbPtsBI8LLMrCvFFpks9D/oTzxnw13RBmMgMlc1bcfQOmE9DZBGB7NCdwOnT7q4TVKhswOITKTQ=="
	proofBytes, err := base64.StdEncoding.DecodeString(proofBase64)
	require.NoError(t, err)

	nonce := []byte("nonce")

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	revealedMessagesBytes := messagesBytes[:1]

	bls := bbs12381g2pub.New()

	t.Run("valid signature proof", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})

	t.Run("test payload revealed bigger from messages", func(t *testing.T) {
		wrongProofBytes, errDecode := base64.StdEncoding.DecodeString(`AAwP/4nFun/RtaXtUVTppUimMRTcEROs3gbjh9iqjGQAsvD+ne2uzME26gY4zNBcMKpvyLD4I6UGm8ATKLQI4OUiBXHNCQZI4YEM5hWI7AzhFXLEEVDFL0Gzr4S04PvcJsmV74BqST8iI1HUO2TCjdT1LkhgPabP/Zy8IpnbWUtLZO1t76NFwCV8+R1YpOozTNKRQQAAAHSpyGry6Rx3PRuOZUeqk4iGFq67iHSiBybjo6muud7aUyCxd9AW3onTlV2Nxz8AJD0AAAACB3FmuAUcklAj5cdSdw7VY57y7p4VmfPCKaEp1SSJTJRZXiE2xUqDntend+tkq+jjHhLCk56zk5GoZzr280IeuLne4WgpB2kNN7n5dqRpy4+UkS5+kiorLtKiJuWhk+OFTiB8jFlTbm0dH3O3tm5CzQAAAAIhY6I8vQ96tdSoyGy09wEMCdWzB06GElVHeQhWVw8fukq1dUAwWRXmZKT8kxDNAlp2NS7fXpEGXZ9fF7+c1IJp`)
		require.NoError(t, errDecode)
		err = bls.VerifyProof(revealedMessagesBytes, wrongProofBytes, nonce, pkBytes)
		require.Error(t, err)
		require.EqualError(t, err, "payload revealed bigger from messages")
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
		require.ErrorContains(t, err, "parse signature proof: parse G1 point: failure [set bytes failed")
	})

	t.Run("invalid input public key", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, []byte("invalid public key"))
		require.Error(t, err)
		require.EqualError(t, err, "parse public key: invalid size of public key")
	})
}

//nolint:lll
func TestBBSG2Pub_VerifyProof_SeveralDisclosedMessages(t *testing.T) {
	pkBase64 := "l0Wtf3gy5f140G5vCoCJw2420hwk6Xw65/DX3ycv1W7/eMky8DyExw+o1s2bmq3sEIJatkiN8f5D4k0766x0UvfbupFX+vVkeqnlOvT6o2cag2osQdMFbBQqAybOM4Gm"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	proofBase64 := "AAQFpAE2VALtmriOzSMk/oqid4uJhPQRUVUuyenL/L4w4ykdyh0jCX64EFqCdLP+n8VrkOKXhHPKPoCOdHBOMv96aM15NFg867/MToMeNN0IFzZkzhs37qk1vWWFKReMF+cRsCAmkHO6An1goNHdY/4XquSV3LwykezraWt8+8bLvVn6ciaXBVxVcYkbIXRsVjqbAAAAdIl/C/W5G1pDbLMrUrBAYdpvzGHG25gktAuUFZb/SkIyy0uhtWJk2v6A+D3zkoEBsgAAAAJY/jfJR9kpGbSY5pfz+qPkqyNOTJbs6OEpfBwYGsyC7hspvBGUOYyvuKlS8SvKAXW7hVawAhYJbvnRwzeiP6P9kbZKtLQZIkRQB+mxRSbMk/0JgE1jApHOlPtgbqI9yIouhK9xT2wVZl79qTAwifonAAAABDTDo5VtXR2gloy+au7ai0wcnnzjMJ6ztQHRI1ApV5VuOQ19TYL7SW+C90p3QSZFQ5gtl90PHaUuEAHIb+7ZgbJvh5sc1DjKfThwPx0Ao0w8+xTbLhNlxvo6VE1cfbiuME+miCAibLgHjksQ8ctl322qnblYJLXiS4lvx/jtGvA3"
	proofBytes, err := base64.StdEncoding.DecodeString(proofBase64)
	require.NoError(t, err)

	nonce := []byte("nonce")

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}
	revealedMessagesBytes := [][]byte{messagesBytes[0], messagesBytes[2]}

	bls := bbs12381g2pub.New()

	t.Run("valid signature", func(t *testing.T) {
		err = bls.VerifyProof(revealedMessagesBytes, proofBytes, nonce, pkBytes)
		require.NoError(t, err)
	})
}

func TestBBSG2Pub_DeriveProof(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}
	bls := bbs12381g2pub.New()

	signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

	nonce := []byte("nonce")
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
		require.EqualError(t, err, "init proof of knowledge signature: invalid size: 6 revealed indexes is "+
			"larger than 4 messages")
	})
}
