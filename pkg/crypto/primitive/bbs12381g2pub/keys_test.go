/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/require"

	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

func TestGenerateKeyPair(t *testing.T) {
	h := sha256.New

	seed := make([]byte, 32)

	pubKey, privKey, err := bbs.GenerateKeyPair(h, seed)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// use random seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, nil)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, privKey)

	// invalid size of seed
	pubKey, privKey, err = bbs.GenerateKeyPair(h, make([]byte, 31))
	require.Error(t, err)
	require.EqualError(t, err, "invalid size of seed")
	require.Nil(t, pubKey)
	require.Nil(t, privKey)
}

func TestPrivateKey_Marshal(t *testing.T) {
	_, privKey, err := generateKeyPairRandom()
	require.NoError(t, err)

	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, privKeyBytes)

	privKeyUnmarshalled, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, privKeyUnmarshalled)
	require.Equal(t, privKey, privKeyUnmarshalled)
}

func TestPrivateKey_PublicKey(t *testing.T) {
	t.Run("random key pair", func(t *testing.T) {
		pubKey, privKey, err := generateKeyPairRandom()
		require.NoError(t, err)

		require.Equal(t, pubKey, privKey.PublicKey())
	})

	t.Run("pre-generated key pair", func(t *testing.T) {
		// original hex seed 746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579
		privateKeyB58 := "5qNVd4Wsp7LPC7vxrbuVMsAkAGif2dA82wm1Wte1zH4Z"
		publicKeyB58 := "25pRBEBDHvG5ryqsEB5tw6eAa3Ds8bx6jMKhEtXnWjCLNg7ikYokwaNtpggZZY3MvWTxBPCidfxFBq2ZiVVTpioCh6GJLs4iESiEydJca9kmeMkEkqK6ePudqoqLHSv4NA7p" // nolint: lll

		privateKey, err := bbs.UnmarshalPrivateKey(base58.Decode(privateKeyB58))
		require.NoError(t, err)

		publicKeyBytes, err := privateKey.PublicKey().Marshal()
		require.Equal(t, publicKeyB58, base58.Encode(publicKeyBytes))
		require.NoError(t, err)
	})

	t.Run("generators", func(t *testing.T) {
		msgCnt := 2
		_, privKey, err := generateKeyPairRandom()
		require.NoError(t, err)

		pkExt, err := privKey.PublicKey().ToPublicKeyWithGenerators(msgCnt)
		require.NoError(t, err)

		bytes := bls12381.NewG1().ToCompressed(pkExt.Q1)
		require.Equal(t,
			"b60acd4b0dc13b580394d2d8bc6c07d452df8e2a7eff93bc9da965b57e076cae640c2858fb0c2eaf242b1bd11107d635",
			hex.EncodeToString(bytes))
		bytes = bls12381.NewG1().ToCompressed(pkExt.Q2)
		require.Equal(t,
			"ad03f655b4c94f312b051aba45977c924bc5b4b1780c969534c183784c7275b70b876db641579604328c0975eaa0a137",
			hex.EncodeToString(bytes))

		require.Equal(t, msgCnt, len(pkExt.H))
		bytes = bls12381.NewG1().ToCompressed(pkExt.H[0])
		require.Equal(t,
			"b63ae18d3edd64a2edd381290f0c68bebabaf3d37bc9dbb0bd5ad8daf03bbd2c48260255ba73f3389d2d5ad82303ac25",
			hex.EncodeToString(bytes))
		bytes = bls12381.NewG1().ToCompressed(pkExt.H[1])
		require.Equal(t,
			"b0b92b79a3e1fc59f39c6b9f78f00b873121c6a4c1814b94c07848efd172762fefbc48447a16f9ba8ed1b638e2933029",
			hex.EncodeToString(bytes))
	})
}

func TestPublicKey_Marshal(t *testing.T) {
	pubKey, _, err := generateKeyPairRandom()
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	require.NotNil(t, pubKeyBytes)

	pubKeyUnmarshalled, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, pubKeyUnmarshalled)
	require.Equal(t, pubKey, pubKeyUnmarshalled)
}

func TestParseMattrKeys(t *testing.T) {
	privKeyB58 := "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj"
	privKeyBytes := base58.Decode(privKeyB58)

	pubKeyB58 := "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu" //nolint:lll
	pubKeyBytes := base58.Decode(pubKeyB58)

	messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}
	signatureBytes, err := bbs.New().Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)

	err = bbs.New().Verify(messagesBytes, signatureBytes, pubKeyBytes)
	require.NoError(t, err)
}

func generateKeyPairRandom() (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbs.GenerateKeyPair(sha256.New, seed)
}
