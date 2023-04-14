/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
)

func TestBBSG2_Sign(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	blsSigner := NewBLS12381G2Signer(privKeyBytes)
	blsVerifier := NewBLS12381G2Verifier(pubKeyBytes)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

	signatureBytes, err := blsSigner.Sign(messagesBytes)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	require.NoError(t, blsVerifier.Verify(messagesBytes, signatureBytes))

	// at least one message must be passed
	signatureBytes, err = blsSigner.Sign([][]byte{})
	require.Error(t, err)
	require.EqualError(t, err, "messages are not defined")
	require.Nil(t, signatureBytes)
}

func TestBBSG2_DeriveProof(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}

	blsSigner := NewBLS12381G2Signer(privKeyBytes)
	blsVerifier := NewBLS12381G2Verifier(pubKeyBytes)

	signatureBytes, err := blsSigner.Sign(messagesBytes)
	require.NoError(t, err)

	require.NoError(t, blsVerifier.Verify(messagesBytes, signatureBytes))

	nonce := []byte("nonce")
	revealedIndexes := []int{0, 2}
	proofBytes, err := blsVerifier.DeriveProof(messagesBytes, signatureBytes, nonce, revealedIndexes)
	require.NoError(t, err)
	require.NotEmpty(t, proofBytes)

	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
	}

	require.NoError(t, blsVerifier.VerifyProof(revealedMessages, proofBytes, nonce))
}

func generateKeyPairRandom() (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbs.GenerateKeyPair(sha256.New, seed)
}
